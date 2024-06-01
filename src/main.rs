use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use dotenvy::dotenv;
use env_logger::Env;
use futures::{
    channel::mpsc::{channel, Receiver},
    lock::Mutex,
    SinkExt, StreamExt,
};
use notify::{
    event::{DataChange, ModifyKind},
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    env,
    fmt::{self, Display},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    thread,
    time::Duration,
};

const PORT: &str = "PORT";
const LOG_TYPE_EXECVE: &str = "EXECVE";

#[derive(Debug, Serialize)]
struct AuditLog {
    log_type: String,
    timestamp: DateTime<Utc>,
    program: String,
    args: Vec<String>,
    argc: u32,
}

#[derive(Debug, Serialize)]
struct AuditLogResponse {
    timestamp: String,
    command: String,
}

impl AuditLog {
    fn get_command(&self) -> String {
        format!(
            "{program} {args}",
            program = self.program,
            args = self.args.join(" ")
        )
    }
}

impl Display for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{timestamp}:  {command}",
            timestamp = self.timestamp,
            command = self.get_command()
        )
    }
}

fn parse_timestamp(log: &str) -> Result<DateTime<Utc>> {
    let timestamp_str = log.strip_prefix("msg=audit(").context(format!(
        "Failed to strip prefix 'msg=audit(' from input [{log}]"
    ))?;

    let mut parts = timestamp_str
        .strip_suffix("):")
        .context(format!("Failed to strip timestamp [{timestamp_str}]"))?
        .split(':');
    let timestamp_str = parts
        .next()
        .context(format!("Failed to split input [{log}] by colon"))?;

    let mut timestamp_parts = timestamp_str.split('.');
    let seconds_str = timestamp_parts.next().context(format!(
        "Failed to split timestamp [{timestamp_str}] by dot"
    ))?;
    let nanos_str = timestamp_parts.next().context(format!(
        "Failed to split timestamp [{timestamp_str}] by dot for nanoseconds"
    ))?;

    let seconds: i64 = seconds_str
        .parse()
        .context(format!("Failed to parse seconds from '{}'", seconds_str))?;
    let nanos = nanos_str
        .parse::<u32>()
        .context(format!("Failed to parse nanoseconds from '{}'", nanos_str))?;

    let datetime = DateTime::from_timestamp(seconds, nanos).context(format!(
        "Failed to create NaiveDateTime from timestamp parts seconds [{seconds}], nanos [{nanos}]"
    ))?;

    Ok(datetime)
}

fn parse_line(line: &str) -> Result<AuditLog> {
    let mut parts = line.split_whitespace();

    let log_type = parts
        .next()
        .context(format!("Missing log type in line: {}", line))?
        .strip_prefix("type=")
        .context(format!("Invalid log type in line: {}", line))?
        .to_string();
    if log_type != LOG_TYPE_EXECVE {
        return Err(anyhow!(
            "Unexpected log type: {}. Expected: {LOG_TYPE_EXECVE}",
            log_type
        ));
    }

    let timestamp_str = parts
        .next()
        .context(format!("Missing timestamp in line: {}", line))?;
    let timestamp =
        parse_timestamp(timestamp_str).context(format!("Invalid timestamp: {}", timestamp_str))?;

    let mut program = String::new();
    let mut args = Vec::new();
    let mut argc = 0;
    for part in parts {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "a0" => {
                    program = value
                        .strip_prefix('"')
                        .context(format!("Unable to strip \" from program: {value}"))?
                        .strip_suffix('"')
                        .context(format!("Unable to strip \" from program: {value}"))?
                        .to_string()
                }
                "argc" => argc = value.parse::<u32>()?,
                _ => {
                    if !value.starts_with('"') {
                        args.push(value.to_string())
                    } else {
                        args.push(
                            value
                                .strip_prefix('"')
                                .context(format!("Unable to strip \" from argument: {value}"))?
                                .strip_suffix('"')
                                .context(format!("Unable to strip \" from argument: {value}"))?
                                .to_string(),
                        )
                    }
                }
            }
        }
    }

    Ok(AuditLog {
        log_type,
        timestamp,
        program,
        args,
        argc,
    })
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);

    let watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        Config::default(),
    )?;

    Ok((watcher, rx))
}

async fn async_watch<P: AsRef<Path>>(
    path: P,
    stream_position: u64,
    audit_logs: web::Data<Mutex<Vec<AuditLog>>>,
) -> notify::Result<()> {
    println!("INFO: Starting watcher");

    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

    let mut position: u64 = stream_position;

    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => {
                if let EventKind::Modify(ModifyKind::Data(DataChange::Any)) = event.kind {
                    thread::sleep(Duration::from_millis(100));

                    let mut file = File::open(event.paths[0].to_str().unwrap())?;
                    file.seek(SeekFrom::Start(position))?;

                    let mut string = String::new();
                    file.read_to_string(&mut string)?;

                    for line in string.lines() {
                        match parse_line(line) {
                            Ok(audit_log) => {
                                let mut audit_logs = audit_logs.lock().await;
                                if audit_logs.is_empty()
                                    || audit_log.timestamp > audit_logs.last().unwrap().timestamp
                                {
                                    println!("INFO: Parsed line: {audit_log}");
                                    audit_logs.push(audit_log);

                                    position = file.stream_position()?;
                                }
                            }
                            Err(e) => {
                                eprintln!("ERROR: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("ERROR: {:?}", e),
        }
    }

    Ok(())
}

fn read_existing_logs<P: AsRef<Path>>(path: &P, audit_logs: &mut Vec<AuditLog>) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut string = String::new();
    file.read_to_string(&mut string)?;

    for line in string.lines() {
        match parse_line(line) {
            Ok(audit_log) => {
                if audit_logs.is_empty()
                    || audit_log.timestamp > audit_logs.last().unwrap().timestamp
                {
                    println!("parsed line: {audit_log}");
                    audit_logs.push(audit_log);
                }
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
            }
        }
    }

    file.stream_position()
        .context("Failed to get stream position")
}

#[get("/audit_logs")]
async fn get_audit_logs(
    audit_logs: web::Data<Mutex<Vec<AuditLog>>>,
    query: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let audit_logs = audit_logs.lock().await;
    let mut audit_logs: Vec<&AuditLog> = audit_logs.iter().collect();
    audit_logs.reverse();

    let page: usize = query.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let page_size: usize = query
        .get("page_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let start = (page - 1) * page_size;
    let end = start + page_size;
    let audit_logs = &audit_logs[start..end.min(audit_logs.len())];

    let response: Vec<AuditLogResponse> = audit_logs
        .iter()
        .map(|log| AuditLogResponse {
            timestamp: log.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            command: log.get_command(),
        })
        .collect();

    HttpResponse::Ok().json(response)
}

async fn run_server(port: u32, audit_logs: web::Data<Mutex<Vec<AuditLog>>>) -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    println!("INFO: Starting server");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new(
                "%a \"%r\" %s %b %D \"%{Referer}i\" \"%{User-Agent}i\" %U %{r}a",
            ))
            .app_data(audit_logs.clone())
            .service(web::scope("/api").service(get_audit_logs))
            .service(actix_files::Files::new("/", "./static").index_file("index.html"))
            .default_service(web::route().to(HttpResponse::NotFound))
    })
    .bind(format!("127.0.0.1:{port}"))?
    .run()
    .await
}

#[actix_rt::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let port = env::var(PORT).unwrap_or("8080".to_string());
    let port = port.parse::<u32>()?;

    let file_path = std::env::args()
        .nth(1)
        .expect("Argument 1 needs to be the log file path");
    let file_path = Path::new(&file_path);

    let mut audit_logs: Vec<AuditLog> = vec![];

    let stream_position = read_existing_logs(&file_path, &mut audit_logs)?;

    let path = file_path
        .parent()
        .context(format!("ERROR: Could not get parent of {file_path:?}"))?;

    let audit_logs = web::Data::new(Mutex::new(audit_logs));

    let server = run_server(port, audit_logs.clone());
    let watcher = async_watch(path, stream_position, audit_logs);

    tokio::select! {
        res = server => {
            if let Err(e) = res {
                eprintln!("ERROR: Server: {:?}", e);
            }
        },
        res = watcher => {
            if let Err(e) = res {
                eprintln!("ERROR: Watcher: {:?}", e);
            }
        },
        _ = tokio::signal::ctrl_c() => {
            println!("INFO: Received Ctrl-C, shutting down.");
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        let line = r#"type=EXECVE msg=audit(1717004049.439:18034): argc=9 a0="/run/current-system/sw/bin/starship" a1="prompt" a2="--right" a3="--terminal-width=120" a4="--keymap=" a5="--status=0" a6="--pipestatus=0" a7="--cmd-duration=1635230" a8="--jobs=0""#;
        let audit_log = parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, LOG_TYPE_EXECVE);
        assert_eq!(audit_log.program, "/run/current-system/sw/bin/starship");
        assert_eq!(audit_log.argc, 9);
        assert_eq!(
            audit_log.args,
            vec![
                "prompt",
                "--right",
                "--terminal-width=120",
                "--keymap=",
                "--status=0",
                "--pipestatus=0",
                "--cmd-duration=1635230",
                "--jobs=0"
            ]
        );
        assert_eq!(audit_log.args.len(), (audit_log.argc - 1) as usize);
    }
}

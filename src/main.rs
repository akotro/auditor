pub mod db_util;
pub mod parser;
pub mod search;
pub mod server;
pub mod watcher;

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::{env, io::Seek, path::Path};

#[actix_rt::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let port = env::var("PORT")
        .unwrap_or("8080".to_string())
        .parse::<u32>()?;

    let file_path = std::env::args()
        .nth(1)
        .expect("Argument 1 needs to be the log file path");
    let file_path = Path::new(&file_path);

    let db_pool = db_util::init_database().await?;

    // let stream_position = parser::AuditLog::read_existing_logs(&file_path, db_pool.clone()).await?;
    let stream_position = std::fs::File::open(file_path)?.stream_position()?;

    let path = file_path
        .parent()
        .context(format!("ERROR: Could not get parent of {file_path:?}"))?;

    let server = server::run_server(port, db_pool.clone());
    let watcher = watcher::async_watch(path, stream_position, db_pool.clone());

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
        let audit_log = parser::AuditLog::parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, parser::LOG_TYPE_EXECVE);
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

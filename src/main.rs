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
        assert_eq!(
            audit_log.timestamp.to_string(),
            String::from("2024-05-29 17:34:09.000000439 UTC")
        );
    }

    #[test]
    fn test_parse_line_with_multiple_args() {
        let line = r#"type=EXECVE msg=audit(1717004049.439:18034): argc=5 a0="/usr/bin/python3" a1="script.py" a2="arg1" a3="arg2" a4="arg3""#;
        let audit_log = parser::AuditLog::parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, parser::LOG_TYPE_EXECVE);
        assert_eq!(audit_log.program, "/usr/bin/python3");
        assert_eq!(audit_log.argc, 5);
        assert_eq!(audit_log.args, vec!["script.py", "arg1", "arg2", "arg3"]);
        assert_eq!(audit_log.args.len(), (audit_log.argc - 1) as usize);
        assert_eq!(
            audit_log.timestamp.to_string(),
            String::from("2024-05-29 17:34:09.000000439 UTC")
        );
    }

    #[test]
    fn test_parse_line_with_special_characters() {
        let line = r#"type=EXECVE msg=audit(1717004049.439:18034): argc=3 a0="/bin/bash" a1="-c" a2="echo \"Hello, World!\"""#;
        let audit_log = parser::AuditLog::parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, parser::LOG_TYPE_EXECVE);
        assert_eq!(audit_log.program, "/bin/bash");
        assert_eq!(audit_log.argc, 3);
        assert_eq!(audit_log.args, vec!["-c", r#"echo \"Hello, World!\""#]);
        assert_eq!(audit_log.args.len(), (audit_log.argc - 1) as usize);
        assert_eq!(
            audit_log.timestamp.to_string(),
            String::from("2024-05-29 17:34:09.000000439 UTC")
        );
    }

    #[test]
    fn test_parse_line_with_no_args() {
        let line = r#"type=EXECVE msg=audit(1717004049.439:18034): argc=1 a0="/bin/ls""#;
        let audit_log = parser::AuditLog::parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, parser::LOG_TYPE_EXECVE);
        assert_eq!(audit_log.program, "/bin/ls");
        assert_eq!(audit_log.argc, 1);
        assert!(audit_log.args.is_empty());
        assert_eq!(
            audit_log.timestamp.to_string(),
            String::from("2024-05-29 17:34:09.000000439 UTC")
        );
    }

    #[test]
    fn test_parse_line_with_missing_fields() {
        let line = r#"type=EXECVE msg=audit(1717004049.439:18034): a0="/bin/ls""#;
        let audit_log = parser::AuditLog::parse_line(line).unwrap();

        assert_eq!(audit_log.log_type, parser::LOG_TYPE_EXECVE);
        assert_eq!(audit_log.program, "/bin/ls");
        assert_eq!(audit_log.argc, 0);
        assert_eq!(audit_log.args.len(), 0);
        assert_eq!(
            audit_log.timestamp.to_string(),
            String::from("2024-05-29 17:34:09.000000439 UTC")
        );
    }

    #[test]
    fn test_parse_line_with_invalid_format() {
        let line = r#"invalid log line"#;
        let audit_log_result = parser::AuditLog::parse_line(line);

        assert!(audit_log_result.is_err());
    }
}

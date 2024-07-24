use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{
    collections::VecDeque,
    fmt::{self, Display},
    fs::File,
    io::{Read, Seek},
    path::Path,
};

use crate::db_util;

pub const LOG_TYPE_EXECVE: &str = "EXECVE";

fn line_regex() -> &'static regex::Regex {
    static REGEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| regex::Regex::new(r#"(\w+)=("(?:\\.|[^"\\])*"|[^\s]+)"#).unwrap())
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub timestamp: String,
    pub command: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct AuditLog {
    pub log_type: String,
    pub timestamp: DateTime<Utc>,
    pub program: String,
    pub args: Vec<String>,
    pub argc: u32,
    pub command: String,
}

impl Display for AuditLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{timestamp}:  {command}",
            timestamp = self.timestamp,
            command = self.command
        )
    }
}

impl AuditLog {
    pub fn get_args_string(&self) -> String {
        let args_string = String::new();

        self.args
            .iter()
            .fold(args_string, |acc, arg| format!("{acc} {arg})"))
    }

    fn parse_timestamp(log: &str) -> Result<DateTime<Utc>> {
        let timestamp_str = log.strip_prefix("audit(").context(format!(
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

    pub fn parse_line(line: &str) -> Result<AuditLog> {
        let mut parts = Vec::new();

        for cap in line_regex().captures_iter(line) {
            parts.push((cap[1].to_string(), cap[2].to_string()));
        }

        let mut parts = parts.iter();

        let log_type = parts
            .next()
            .context(format!("Missing log type in line: {}", line))?
            .1
            .to_string();
        if log_type != LOG_TYPE_EXECVE {
            return Err(anyhow!(""));
        }

        let timestamp_str = &parts
            .next()
            .context(format!("Missing timestamp in line: {}", line))?
            .1;
        let timestamp = Self::parse_timestamp(timestamp_str)
            .context(format!("Invalid timestamp: {}", timestamp_str))?;

        println!("parts: {parts:#?}");

        let mut program = String::new();
        let mut args = Vec::new();
        let mut argc = 0;
        for (key, value) in parts {
            match key.as_str() {
                "a0" => {
                    program = value
                        .strip_prefix('"')
                        .context(format!(
                            "Unable to strip \" from program: '{value}' while parsing '{line}'"
                        ))?
                        .strip_suffix('"')
                        .context(format!(
                            "Unable to strip \" from program: '{value}' while parsing '{line}'"
                        ))?
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
                                    .context(format!("Unable to strip \" from argument: '{value}' while parsing '{line}'"))?
                                    .strip_suffix('"')
                                    .context(format!("Unable to strip \" from argument: '{value}' while parsing '{line}'"))?
                                    .to_string(),
                            )
                    }
                }
            }
        }

        let command = format!("{program} {args}", program = program, args = args.join(" "));

        Ok(AuditLog {
            log_type,
            timestamp,
            program,
            args,
            argc,
            command,
        })
    }

    pub async fn read_existing_logs<P: AsRef<Path>>(
        path: &P,
        db_pool: sqlx::Pool<sqlx::Sqlite>,
    ) -> Result<u64> {
        let mut audit_logs: VecDeque<AuditLog> = vec![].into();

        let last_audit_log_response = db_util::fetch_last_audit_log(&db_pool)
            .await
            .with_context(|| "ERROR: Could not fetch last audit log")?;

        let mut remove_first_log = false;
        if let Some(last_audit_log_response) = last_audit_log_response {
            let last_audit_log = AuditLog {
                log_type: LOG_TYPE_EXECVE.to_string(),
                timestamp: DateTime::parse_from_rfc3339(&last_audit_log_response.timestamp)
                    .with_context(|| {
                        "ERROR: Could not convert last audit log timestamp to datetime"
                    })?
                    .into(),
                command: last_audit_log_response.command,
                ..Default::default()
            };
            audit_logs.push_back(last_audit_log);

            remove_first_log = true;
        }

        let mut file = File::open(path)?;
        let mut string = String::new();
        file.read_to_string(&mut string)?;

        for line in string.lines() {
            match Self::parse_line(line) {
                Ok(audit_log) => {
                    if audit_logs.is_empty()
                        || audit_log.timestamp > audit_logs.iter().last().unwrap().timestamp
                    {
                        // println!("INFO: parsed line: {audit_log}");
                        audit_logs.push_back(audit_log);
                    }
                }
                Err(e) => {
                    let error_message = e.to_string();
                    if !error_message.is_empty() {
                        eprintln!("ERROR: {}", error_message);
                    }
                }
            }
        }

        if remove_first_log {
            if let Some(last_audit_log) = audit_logs.pop_front() {
                println!("INFO: last audit log: {last_audit_log}");
            }
        }

        for audit_log in audit_logs {
            db_util::insert_audit_log(&db_pool, &audit_log)
                .await
                .with_context(|| "ERROR: Could not insert audit log:")?;
        }

        file.stream_position()
            .context("ERROR: Failed to get stream position")
    }
}

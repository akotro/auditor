use anyhow::{anyhow, Result};
use dotenvy::dotenv;
use sqlx::{
    migrate::{MigrateDatabase, Migrator},
    pool::PoolConnection,
    query, query_as,
    sqlite::SqliteQueryResult,
    Pool, Sqlite, SqlitePool,
};

use crate::parser;

const DATA_DIR: &str = "./";

static MIGRATOR: Migrator = sqlx::migrate!();

pub async fn init_database() -> Result<Pool<Sqlite>> {
    dotenv().ok();

    let data_dir = std::env::var("DATA_DIR").unwrap_or(DATA_DIR.to_string());
    if !std::path::Path::new(&data_dir).exists() {
        std::fs::create_dir_all(&data_dir)?;
    }

    let db_url = format!("sqlite:{data_dir}/auditor.db");

    if !Sqlite::database_exists(&db_url).await.unwrap_or(false) {
        Sqlite::create_database(&db_url).await?;
    }

    let pool = SqlitePool::connect(&db_url).await.unwrap();

    MIGRATOR.run(&pool).await?;

    Ok(pool)
}

pub async fn get_connection(pool: &Pool<Sqlite>) -> Option<PoolConnection<Sqlite>> {
    pool.acquire().await.ok()
}

pub async fn fetch_audit_logs(pool: &Pool<Sqlite>) -> Result<Vec<parser::AuditLogResponse>> {
    let mut conn = get_connection(pool)
        .await
        .ok_or(anyhow!("ERROR: Failed to get connection from db pool"))?;

    let audit_logs = match query_as!(
        parser::AuditLogResponse,
        "SELECT timestamp, command FROM audit_log ORDER BY timestamp DESC"
    )
    .fetch_all(&mut *conn)
    .await
    {
        Ok(query_result) => query_result,
        Err(err) => {
            return Err(anyhow!("ERROR: Could not fetch audit_logs: {err}"));
        }
    };

    Ok(audit_logs)
}

pub async fn fetch_audit_logs_paginated(
    pool: &Pool<Sqlite>,
    page: i64,
    page_size: i64,
) -> Result<Vec<parser::AuditLogResponse>> {
    let mut conn = get_connection(pool)
        .await
        .ok_or(anyhow!("ERROR: Failed to get connection from db pool"))?;

    let offset = (page - 1) * page_size;

    let audit_logs = match query_as!(
        parser::AuditLogResponse,
        "SELECT timestamp, command FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        page_size,
        offset
    )
    .fetch_all(&mut *conn)
    .await
    {
        Ok(query_result) => query_result,
        Err(err) => {
            return Err(anyhow!(
                "ERROR: Could not fetch paginated audit_logs: {err}"
            ));
        }
    };

    Ok(audit_logs)
}

pub async fn fetch_last_audit_log(pool: &Pool<Sqlite>) -> Result<Option<parser::AuditLogResponse>> {
    let mut conn = get_connection(pool)
        .await
        .ok_or(anyhow!("ERROR: Failed to get connection from db pool"))?;

    let last_audit_log = match query_as!(
        parser::AuditLogResponse,
        "SELECT timestamp, command FROM audit_log ORDER BY timestamp DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(query_result) => query_result,
        Err(err) => {
            return Err(anyhow!(
                "ERROR: Could not fetch paginated audit_logs: {err}"
            ));
        }
    };

    Ok(last_audit_log)
}

pub async fn insert_audit_log(
    pool: &Pool<Sqlite>,
    new_log: &parser::AuditLog,
) -> Result<SqliteQueryResult> {
    let mut conn = get_connection(pool)
        .await
        .ok_or(anyhow!("ERROR: Failed to get connection from db pool"))?;

    let args = new_log.get_args_string();

    let query = query_as!(
        AuditLog,
        "INSERT INTO audit_log (log_type, timestamp, program, args, argc, command) VALUES (?, ?, ?, ?, ?, ?)",
        new_log.log_type,
        new_log.timestamp,
        new_log.program,
        args,
        new_log.argc,
        new_log.command,
    );

    let result = match query.execute(&mut *conn).await {
        Ok(query_result) => query_result,
        Err(err) => {
            return Err(anyhow!("ERROR: Could not create audit_log: {err}"));
        }
    };

    Ok(result)
}

pub async fn clear_audit_logs(pool: &Pool<Sqlite>) -> Result<SqliteQueryResult> {
    let mut conn = get_connection(pool)
        .await
        .ok_or(anyhow!("ERROR: Failed to get connection from db pool"))?;

    let two_weeks_ago = chrono::Utc::now() - chrono::Duration::weeks(2);
    let two_weeks_ago_str = two_weeks_ago.to_rfc3339();

    let query = query!(
        "DELETE FROM audit_log WHERE timestamp < ?",
        two_weeks_ago_str
    );

    let result = match query.execute(&mut *conn).await {
        Ok(query_result) => query_result,
        Err(err) => {
            return Err(anyhow!("ERROR: Could not clear audit_logs: {err}"));
        }
    };

    Ok(result)
}

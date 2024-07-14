use std::{collections::HashMap, env, path::PathBuf};

use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer};
use env_logger::Env;

use crate::{db_util, search};

#[get("/audit_logs")]
async fn get_audit_logs(
    pool: web::Data<sqlx::SqlitePool>,
    params: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let page: i64 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let page_size: i64 = params
        .get("page_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let audit_logs = match db_util::fetch_audit_logs_paginated(&pool, page, page_size).await {
        Ok(audit_logs) => audit_logs,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    HttpResponse::Ok().json(audit_logs)
}

#[get("/audit_logs/search")]
async fn search_audit_logs(
    pool: web::Data<sqlx::SqlitePool>,
    params: web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let audit_logs = match db_util::fetch_audit_logs(&pool).await {
        Ok(audit_logs) => audit_logs,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    let query = params.get("q").unwrap_or(&String::new()).to_owned();
    let n: usize = params.get("n").and_then(|s| s.parse().ok()).unwrap_or(20);

    let results = search::fuzzy_search_best_n(&query, &audit_logs, n);

    HttpResponse::Ok().json(results)
}

#[get("/audit_logs/clear")]
async fn clear_audit_logs(pool: web::Data<sqlx::SqlitePool>) -> HttpResponse {
    match db_util::clear_audit_logs(&pool).await {
        Ok(result) => result,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    println!("INFO: Audit logs older than 2 weeks cleared successfully");

    HttpResponse::Ok().body("Audit logs older than 2 weeks cleared successfully")
}

pub async fn run_server(port: u32, db_pool: sqlx::Pool<sqlx::Sqlite>) -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));

    let mut static_dir = env::current_exe()
        .ok()
        .and_then(|pb| pb.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("static");
    if cfg!(debug_assertions) {
        static_dir = "./static".into();
    }

    println!("INFO: Starting server");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::new(
                "%a \"%r\" %s %b %D \"%{Referer}i\" \"%{User-Agent}i\" %U %{r}a",
            ))
            .app_data(web::Data::new(db_pool.clone()))
            .service(
                web::scope("/api")
                    .service(get_audit_logs)
                    .service(search_audit_logs)
                    .service(clear_audit_logs),
            )
            .service(actix_files::Files::new("/", static_dir.clone()).index_file("index.html"))
            .default_service(web::route().to(HttpResponse::NotFound))
    })
    .bind(format!("127.0.0.1:{port}"))?
    .run()
    .await
}

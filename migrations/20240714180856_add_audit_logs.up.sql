-- Add up migration script here
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    program TEXT NOT NULL,
    args TEXT NOT NULL,
    argc INTEGER NOT NULL,
    command TEXT NOT NULL
);

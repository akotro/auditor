use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    thread,
    time::Duration,
};

use futures::{
    channel::mpsc::{channel, Receiver},
    lock::Mutex,
    SinkExt, StreamExt,
};
use notify::{
    event::{DataChange, ModifyKind},
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};

use crate::{db_util, parser};

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

pub async fn async_watch<P: AsRef<Path>>(
    path: P,
    stream_position: u64,
    db_pool: sqlx::Pool<sqlx::Sqlite>,
) -> notify::Result<()> {
    println!("INFO: Starting watcher");

    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

    let mut position: u64 = stream_position;

    let last_audit_log_mutex: Mutex<Option<parser::AuditLog>> = Mutex::new(None);

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
                        match parser::AuditLog::parse_line(line) {
                            Ok(audit_log) => {
                                let mut last_audit_log = last_audit_log_mutex.lock().await;
                                if last_audit_log.is_none() {
                                    *last_audit_log = Some(audit_log);
                                } else if last_audit_log
                                    .clone()
                                    .is_some_and(|lal| audit_log.timestamp > lal.timestamp)
                                {
                                    // println!("INFO: Parsed line: {audit_log}");

                                    if let Err(insert_error) =
                                        db_util::insert_audit_log(&db_pool, &audit_log).await
                                    {
                                        println!(
                                            "ERROR: Could not insert new audit log: {insert_error}"
                                        );
                                    }

                                    *last_audit_log = Some(audit_log);

                                    position = file.stream_position()?;
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
                }
            }
            Err(e) => eprintln!("ERROR: {:?}", e),
        }
    }

    Ok(())
}

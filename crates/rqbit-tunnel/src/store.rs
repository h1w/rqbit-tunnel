use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::sync::Condvar;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;
use tokio::task::spawn_blocking;
use uuid::Uuid;

use crate::model::{TrafficTotals, UserRecord};

const SCHEMA_VERSION: &str = "1";

const MIGRATIONS: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY NOT NULL,
 name TEXT NOT NULL UNIQUE,
 public_key BLOB NOT NULL UNIQUE,
 enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
 created_at INTEGER NOT NULL,
 reset_at INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_totals (
 user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 upload_bytes INTEGER NOT NULL DEFAULT 0 CHECK (upload_bytes >= 0),
 download_bytes INTEGER NOT NULL DEFAULT 0 CHECK (download_bytes >= 0),
 updated_at INTEGER NOT NULL
);
"#;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to create SQLite directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the system clock is before the Unix epoch: {0}")]
    Clock(#[from] std::time::SystemTimeError),
    #[error("SQLite counter {direction}={value} is outside SQLite's signed range")]
    CounterOutOfRange { direction: &'static str, value: u64 },
    #[error("stored enabled value for user {user_id} is invalid: {value}")]
    InvalidEnabled { user_id: Uuid, value: i64 },
    #[error("stored public key has invalid length {0}")]
    InvalidPublicKeyLength(usize),
    #[error("stored {direction} counter for user {user_id} is invalid")]
    InvalidStoredCounter {
        user_id: Uuid,
        direction: &'static str,
    },
    #[error("stored user id is invalid: {value}")]
    InvalidUserId {
        value: String,
        #[source]
        source: uuid::Error,
    },
    #[error("SQLite connection mutex was poisoned")]
    PoisonedConnection,
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("stored schema version {0} is unsupported")]
    UnsupportedSchemaVersion(String),
    #[error("user {0} does not exist")]
    UserNotFound(Uuid),
    #[error("system timestamp is outside SQLite's signed range")]
    TimestampOutOfRange,
    #[error("SQLite worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub struct ServerStore {
    connection: Arc<Mutex<Connection>>,
    #[cfg(test)]
    set_enabled_pause: Arc<Mutex<Option<Arc<SetEnabledPause>>>>,
}

pub(crate) struct StoredUser {
    pub(crate) record: UserRecord,
    pub(crate) traffic: TrafficTotals,
}

#[cfg(test)]
pub(crate) struct SetEnabledPause {
    started: tokio::sync::Notify,
    release: (Mutex<bool>, Condvar),
}

#[cfg(test)]
impl SetEnabledPause {
    fn new() -> Self {
        Self {
            started: tokio::sync::Notify::new(),
            release: (Mutex::new(false), Condvar::new()),
        }
    }

    pub(crate) async fn wait_started(&self) {
        self.started.notified().await;
    }

    pub(crate) fn release(&self) {
        let mut released = self
            .release
            .0
            .lock()
            .expect("set-enabled pause mutex poisoned");
        *released = true;
        self.release.1.notify_all();
    }

    fn wait_for_release(&self) {
        let released = self
            .release
            .0
            .lock()
            .expect("set-enabled pause mutex poisoned");
        let _released = self
            .release
            .1
            .wait_while(released, |released| !*released)
            .expect("set-enabled pause mutex poisoned");
    }
}

impl ServerStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let database_path = path.as_ref().to_path_buf();
        let directory = database_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf);

        let connection = spawn_blocking(move || -> Result<Connection, StoreError> {
            if let Some(directory) = directory {
                std::fs::create_dir_all(&directory).map_err(|source| {
                    StoreError::CreateDirectory {
                        path: directory,
                        source,
                    }
                })?;
            }

            let mut connection = Connection::open(database_path)?;
            connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
            migrate(&mut connection)?;
            Ok(connection)
        })
        .await??;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            #[cfg(test)]
            set_enabled_pause: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    pub(crate) fn pause_next_set_enabled(&self) -> Arc<SetEnabledPause> {
        let pause = Arc::new(SetEnabledPause::new());
        let mut slot = self
            .set_enabled_pause
            .lock()
            .expect("set-enabled pause mutex poisoned");
        assert!(slot.is_none(), "a set-enabled pause is already installed");
        *slot = Some(Arc::clone(&pause));
        pause
    }

    pub async fn create_user(&self, user: &UserRecord) -> Result<(), StoreError> {
        let user = user.clone();

        self.run(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO users (id, name, public_key, enabled, created_at, reset_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    user.id.to_string(),
                    user.name,
                    user.public_key.as_slice(),
                    i64::from(user.enabled),
                    user.created_at,
                    user.reset_at,
                ],
            )?;
            transaction.execute(
                "INSERT INTO traffic_totals (user_id, updated_at) VALUES (?1, ?2)",
                params![user.id.to_string(), user.created_at],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn delete_user(&self, user_id: Uuid) -> Result<(), StoreError> {
        self.run(move |connection| {
            let transaction = connection.transaction()?;
            require_user(
                transaction.execute(
                    "DELETE FROM users WHERE id = ?1",
                    params![user_id.to_string()],
                )?,
                user_id,
            )?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn increment_traffic(
        &self,
        user_id: Uuid,
        traffic: TrafficTotals,
    ) -> Result<(), StoreError> {
        if traffic == TrafficTotals::default() {
            return Ok(());
        }

        let upload = sqlite_counter(traffic.upload, "upload")?;
        let download = sqlite_counter(traffic.download, "download")?;
        let updated_at = current_unix_seconds()?;

        self.run(move |connection| {
            let transaction = connection.transaction()?;
            require_user(
                transaction.execute(
                    "UPDATE traffic_totals
                     SET upload_bytes = upload_bytes + ?1,
                         download_bytes = download_bytes + ?2,
                         updated_at = ?3
                     WHERE user_id = ?4",
                    params![upload, download, updated_at, user_id.to_string()],
                )?,
                user_id,
            )?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn load_users(&self) -> Result<Vec<StoredUser>, StoreError> {
        self.run(|connection| {
            let mut statement = connection.prepare(
                "SELECT users.id, users.name, users.public_key, users.enabled, users.created_at,
                        users.reset_at, traffic_totals.upload_bytes, traffic_totals.download_bytes
                 FROM users
                 INNER JOIN traffic_totals ON traffic_totals.user_id = users.id
                 ORDER BY users.created_at, users.id",
            )?;
            let mut rows = statement.query([])?;
            let mut users = Vec::new();

            while let Some(row) = rows.next()? {
                let id_text: String = row.get(0)?;
                let id = Uuid::parse_str(&id_text).map_err(|source| StoreError::InvalidUserId {
                    value: id_text,
                    source,
                })?;
                let public_key: Vec<u8> = row.get(2)?;
                let public_key: [u8; 32] =
                    public_key.try_into().map_err(|public_key: Vec<u8>| {
                        StoreError::InvalidPublicKeyLength(public_key.len())
                    })?;
                let enabled: i64 = row.get(3)?;
                let enabled = match enabled {
                    0 => false,
                    1 => true,
                    value => return Err(StoreError::InvalidEnabled { user_id: id, value }),
                };
                let upload: i64 = row.get(6)?;
                let download: i64 = row.get(7)?;
                let upload =
                    u64::try_from(upload).map_err(|_| StoreError::InvalidStoredCounter {
                        user_id: id,
                        direction: "upload",
                    })?;
                let download =
                    u64::try_from(download).map_err(|_| StoreError::InvalidStoredCounter {
                        user_id: id,
                        direction: "download",
                    })?;

                users.push(StoredUser {
                    record: UserRecord {
                        id,
                        name: row.get(1)?,
                        public_key,
                        enabled,
                        created_at: row.get(4)?,
                        reset_at: row.get(5)?,
                    },
                    traffic: TrafficTotals { upload, download },
                });
            }

            Ok(users)
        })
        .await
    }

    pub async fn reset_traffic(&self, user_id: Uuid, reset_at: i64) -> Result<(), StoreError> {
        self.run(move |connection| {
            let transaction = connection.transaction()?;
            require_user(
                transaction.execute(
                    "UPDATE users SET reset_at = ?1 WHERE id = ?2",
                    params![reset_at, user_id.to_string()],
                )?,
                user_id,
            )?;
            require_user(
                transaction.execute(
                    "UPDATE traffic_totals
                     SET upload_bytes = 0, download_bytes = 0, updated_at = ?1
                     WHERE user_id = ?2",
                    params![reset_at, user_id.to_string()],
                )?,
                user_id,
            )?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn set_enabled(&self, user_id: Uuid, enabled: bool) -> Result<(), StoreError> {
        #[cfg(test)]
        let pause = self
            .set_enabled_pause
            .lock()
            .expect("set-enabled pause mutex poisoned")
            .take();

        self.run(move |connection| {
            let transaction = connection.transaction()?;
            require_user(
                transaction.execute(
                    "UPDATE users SET enabled = ?1 WHERE id = ?2",
                    params![i64::from(enabled), user_id.to_string()],
                )?,
                user_id,
            )?;
            #[cfg(test)]
            if let Some(pause) = pause {
                pause.started.notify_one();
                pause.wait_for_release();
            }
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let connection = Arc::clone(&self.connection);

        spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| StoreError::PoisonedConnection)?;
            operation(&mut connection)
        })
        .await?
    }
}

pub(crate) fn current_unix_seconds() -> Result<i64, StoreError> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    i64::try_from(seconds).map_err(|_| StoreError::TimestampOutOfRange)
}

fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction()?;
    transaction.execute_batch(MIGRATIONS)?;

    let version: Option<String> = transaction
        .query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params!["schema_version"],
            |row| row.get(0),
        )
        .optional()?;

    match version {
        Some(version) if version == SCHEMA_VERSION => {}
        Some(version) => return Err(StoreError::UnsupportedSchemaVersion(version)),
        None => {
            transaction.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)",
                params!["schema_version", SCHEMA_VERSION],
            )?;
        }
    }

    transaction.commit()?;
    Ok(())
}

fn require_user(changed: usize, user_id: Uuid) -> Result<(), StoreError> {
    if changed == 0 {
        return Err(StoreError::UserNotFound(user_id));
    }

    Ok(())
}

fn sqlite_counter(value: u64, direction: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CounterOutOfRange { direction, value })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;
    use uuid::Uuid;

    use crate::{
        model::{TrafficTotals, UserRecord},
        paths::ServerPaths,
    };

    use super::ServerStore;

    #[tokio::test]
    async fn migrations_are_idempotent_and_delete_cascades_counters() {
        let directory = tempfile::tempdir().unwrap();
        let database_path = ServerPaths::under(directory.path()).database_path();
        let store = ServerStore::open(database_path.clone()).await.unwrap();
        let _second_open = ServerStore::open(database_path.clone()).await.unwrap();
        let user = UserRecord {
            id: Uuid::new_v4(),
            name: "alice".to_owned(),
            public_key: [7; 32],
            enabled: true,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            reset_at: None,
        };

        store.create_user(&user).await.unwrap();
        store
            .increment_traffic(
                user.id,
                TrafficTotals {
                    upload: 9,
                    download: 14,
                },
            )
            .await
            .unwrap();
        store.delete_user(user.id).await.unwrap();

        let (journal_mode, schema_version, counter_rows) = tokio::task::spawn_blocking(move || {
            let connection = Connection::open(database_path)?;
            let journal_mode: String =
                connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            let schema_version: String = connection.query_row(
                "SELECT value FROM settings WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )?;
            let counter_rows: i64 =
                connection
                    .query_row("SELECT COUNT(*) FROM traffic_totals", [], |row| row.get(0))?;
            Ok::<_, rusqlite::Error>((journal_mode, schema_version, counter_rows))
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(journal_mode, "wal");
        assert_eq!(schema_version, "1");
        assert_eq!(counter_rows, 0);
    }
}

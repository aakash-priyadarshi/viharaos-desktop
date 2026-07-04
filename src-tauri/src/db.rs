pub mod schema;
pub mod models;

use std::path::Path;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use thiserror::Error;

pub type DbPool = Pool<SqliteConnectionManager>;
pub type DbResult<T> = Result<T, DbError>;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Connection pool error: {0}")]
    Pool(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Validation: {0}")]
    Validation(String),
}

pub struct Database {
    pool: DbPool,
}

impl Database {
    pub fn new(path: &Path) -> DbResult<Self> {
        let manager = SqliteConnectionManager::file(path)
            .with_init(|c| {
                c.execute_batch(
                    "PRAGMA journal_mode = WAL; \
                     PRAGMA foreign_keys = ON; \
                     PRAGMA synchronous = NORMAL; \
                     PRAGMA busy_timeout = 5000;",
                )
            });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|e| DbError::Pool(e.to_string()))?;

        let db = Self { pool };
        db.init_schema()?;
        Ok(db)
    }

    pub fn conn(&self) -> DbResult<r2d2::PooledConnection<SqliteConnectionManager>> {
        self.pool
            .get()
            .map_err(|e| DbError::Pool(e.to_string()))
    }

    fn init_schema(&self) -> DbResult<()> {
        let conn = self.conn()?;
        schema::run_migrations(&conn)?;
        Ok(())
    }
}

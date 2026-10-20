use sqlx::sqlite::{SqlitePoolOptions, SqliteConnectOptions};
use sqlx::FromRow;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Pool = sqlx::SqlitePool;

/// Row returned by the one-shot consume query. Plain `query_as` (not the `query!` macro) is
/// used throughout this module deliberately: it keeps the build independent of a live
/// database at compile time, which matters for a straightforward Docker build.
#[derive(Debug, FromRow)]
pub struct ConsumedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub requires_passphrase: bool,
}

#[derive(Debug, FromRow)]
pub struct SecretMeta {
    pub requires_passphrase: bool,
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

/// Opens (and creates, if missing) the sqlite database file, then runs migrations.
pub async fn init_pool(database_url: &str) -> anyhow::Result<Pool> {
    let options = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_secret(
    pool: &Pool,
    id: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    salt: Option<&[u8]>,
    requires_passphrase: bool,
    created_at: i64,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO secrets (id, ciphertext, nonce, salt, requires_passphrase, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(id)
    .bind(ciphertext)
    .bind(nonce)
    .bind(salt)
    .bind(requires_passphrase)
    .bind(created_at)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Metadata-only lookup for the reveal (burn-confirmation) page. Never returns ciphertext,
/// and never deletes the row -- a GET here must be side-effect free.
pub async fn get_secret_meta(pool: &Pool, id: &str, now: i64) -> Result<Option<SecretMeta>, sqlx::Error> {
    sqlx::query_as::<_, SecretMeta>(
        "SELECT requires_passphrase FROM secrets WHERE id = ?1 AND expires_at > ?2",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(pool)
    .await
}

/// Atomically fetches and deletes a secret in one statement, so two concurrent viewers can
/// never both read it. Returns None if the id is missing, expired, or already consumed.
pub async fn consume_secret(pool: &Pool, id: &str, now: i64) -> Result<Option<ConsumedSecret>, sqlx::Error> {
    sqlx::query_as::<_, ConsumedSecret>(
        "DELETE FROM secrets WHERE id = ?1 AND expires_at > ?2
         RETURNING ciphertext, nonce, salt, requires_passphrase",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(pool)
    .await
}

/// Deletes everything past its TTL. Called by the background reaper; returns rows removed.
pub async fn reap_expired(pool: &Pool, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM secrets WHERE expires_at <= ?1")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

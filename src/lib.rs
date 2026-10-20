pub mod db;
mod error;
mod handlers;
mod models;
mod security;
mod static_files;

use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Runtime configuration. Normally read once at startup from the environment via
/// `from_env`; tests construct it directly (all fields are public) to avoid depending on
/// process-global env vars, which would be racy across concurrently-running tests.
#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub max_secret_bytes: usize,
    /// Allowed TTL choices offered on the create form, in seconds. `create_secret` rejects
    /// any `ttl_secs` not found in this list.
    pub ttl_choices_secs: Vec<(&'static str, i64)>,
}

impl Config {
    pub fn from_env() -> Self {
        let port = std::env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);

        let database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:data/secrets.db".to_string());

        let max_secret_bytes = std::env::var("MAX_SECRET_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(262_144);

        Config {
            port,
            database_url,
            max_secret_bytes,
            ttl_choices_secs: vec![
                ("5 minutes", 5 * 60),
                ("1 hour", 60 * 60),
                ("1 day", 24 * 60 * 60),
                ("1 week", 7 * 24 * 60 * 60),
            ],
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: db::Pool,
    pub config: Arc<Config>,
}

/// Builds the full axum app (routes + middleware) from a ready `AppState`. Shared by
/// `main` and the integration tests so the thing under test is exactly what ships.
pub fn build_router(state: AppState) -> Router {
    // Body-size cap accounts for base64 (~4/3 blowup) plus JSON/field overhead around the
    // ciphertext, so a MAX_SECRET_BYTES-sized plaintext still fits comfortably.
    let max_request_bytes = state.config.max_secret_bytes * 2 + 4096;

    Router::new()
        .route("/", get(handlers::create_page))
        .route("/api/secrets", post(handlers::create_secret))
        .route("/s/{id}", get(handlers::reveal_page))
        .route("/api/secrets/{id}/consume", post(handlers::consume_secret))
        .route("/healthz", get(handlers::healthz))
        .route("/static/{*path}", get(static_files::serve))
        .fallback(handlers::fallback_404)
        .layer(axum::middleware::from_fn(security::security_headers))
        .layer(RequestBodyLimitLayer::new(max_request_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Background task that deletes expired secrets every 60s, independent of whether
/// anyone ever tries to view them.
pub fn spawn_reaper(pool: db::Pool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            match db::reap_expired(&pool, db::now_secs()).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(count = n, "reaped expired secrets"),
                Err(err) => tracing::warn!(error = %err, "reaper query failed"),
            }
        }
    });
}

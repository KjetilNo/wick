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
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_governor::GovernorLayer;
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
    pub max_attachment_bytes: usize,
    /// Allowed TTL choices offered on the create form, in seconds. `create_secret` rejects
    /// any `ttl_secs` not found in this list.
    pub ttl_choices_secs: Vec<(&'static str, i64)>,
    /// Per-IP token bucket for `POST /api/secrets`: this many requests may burst through,
    /// refilling at `rate_limit_per_second` per second.
    pub rate_limit_burst: u32,
    pub rate_limit_per_second: u64,
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

        let max_attachment_bytes = std::env::var("MAX_ATTACHMENT_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        let rate_limit_burst = std::env::var("RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);

        let rate_limit_per_second = std::env::var("RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        Config {
            port,
            database_url,
            max_secret_bytes,
            max_attachment_bytes,
            ttl_choices_secs: vec![
                ("5 minutes", 5 * 60),
                ("1 hour", 60 * 60),
                ("1 day", 24 * 60 * 60),
                ("1 week", 7 * 24 * 60 * 60),
            ],
            rate_limit_burst,
            rate_limit_per_second,
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
    // ciphertext and the optional attachment, so a payload at either limit still fits.
    let max_request_bytes =
        (state.config.max_secret_bytes + state.config.max_attachment_bytes) * 2 + 4096;

    // Per-IP token bucket on secret creation only -- consume attempts are already
    // protected by unguessable 128-bit ids, so there's nothing to gain throttling those.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(state.config.rate_limit_per_second)
            .burst_size(state.config.rate_limit_burst)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("invalid rate limit configuration"),
    );
    let gc_conf = governor_conf.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            gc_conf.limiter().retain_recent();
        }
    });

    let create_secret_route =
        post(handlers::create_secret).layer(GovernorLayer::new(governor_conf));

    Router::new()
        .route("/", get(handlers::create_page))
        .route("/api/secrets", create_secret_route)
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

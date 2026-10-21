use wick::{build_router, spawn_reaper, AppState, Config};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    tracing::info!(
        port = config.port,
        database_url = %redact_credentials(&config.database_url),
        "starting wick"
    );

    let db = wick::db::init_pool(&config.database_url).await?;
    let port = config.port;

    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
    };

    let app = build_router(state);

    spawn_reaper(db);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Masks the `user:pass@` userinfo portion of a connection string before it's logged, so a
/// future credentialed DATABASE_URL (e.g. postgres) can't end up in plaintext logs.
fn redact_credentials(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let Some(at) = rest.rfind('@') else {
        return url.to_string();
    };
    format!("{}://***@{}", &url[..scheme_end], &rest[at + 1..])
}

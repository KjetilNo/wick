use wick::{build_router, spawn_reaper, AppState, Config};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    tracing::info!(port = config.port, database_url = %config.database_url, "starting wick");

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
    axum::serve(listener, app).await?;

    Ok(())
}

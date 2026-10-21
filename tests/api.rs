//! End-to-end tests against a real (temp-file) sqlite DB and a real axum server bound to an
//! ephemeral port. These exercise exactly the guarantees the design is built around: a
//! secret can be consumed once and only once, expired secrets are inaccessible, and
//! oversized payloads are rejected.

use serde_json::{json, Value};
use std::net::SocketAddr;

/// Spins up the app on an ephemeral port against a throwaway sqlite file, and returns its
/// base URL. The server runs for the lifetime of the test process (tests run in separate
/// processes per binary, so no explicit shutdown is needed).
async fn spawn_app() -> String {
    let db_path = std::env::temp_dir().join(format!("wick-test-{}.db", uuid_like()));
    let database_url = format!("sqlite:{}", db_path.display());

    let pool = wick::db::init_pool(&database_url)
        .await
        .expect("failed to init test db");

    // Constructed directly (not via Config::from_env) so tests never touch process-global
    // env vars -- those would race across the concurrently-running #[tokio::test] fns.
    let config = wick::Config {
        port: 0,
        database_url: database_url.clone(),
        max_secret_bytes: 1024,
        ttl_choices_secs: vec![("1 second", 1), ("5 minutes", 300)],
    };
    let state = wick::AppState {
        db: pool.clone(),
        config: std::sync::Arc::new(config),
    };

    let app = wick::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{addr}")
}

fn uuid_like() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sample_create_body(ttl_secs: i64) -> Value {
    json!({
        "ciphertext": base64url("hello-ciphertext"),
        "nonce": base64url("123456789012"), // 12 bytes
        "salt": null,
        "requires_passphrase": false,
        "ttl_secs": ttl_secs,
    })
}

fn base64url(s: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

#[tokio::test]
async fn create_then_consume_then_second_consume_404s() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let create_res = client
        .post(format!("{base}/api/secrets"))
        .json(&sample_create_body(300))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), 200);
    let body: Value = create_res.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    // Reveal page shows the secret as available beforehand.
    let reveal_res = client.get(format!("{base}/s/{id}")).send().await.unwrap();
    assert_eq!(reveal_res.status(), 200);
    let html = reveal_res.text().await.unwrap();
    assert!(html.contains("reveal-button") || html.contains("Reveal"));

    // First consume succeeds.
    let consume_res = client
        .post(format!("{base}/api/secrets/{id}/consume"))
        .header("X-Requested-With", "wick")
        .send()
        .await
        .unwrap();
    assert_eq!(consume_res.status(), 200);
    let consumed: Value = consume_res.json().await.unwrap();
    assert!(!consumed["ciphertext"].as_str().unwrap().is_empty());

    // Second consume: gone.
    let second = client
        .post(format!("{base}/api/secrets/{id}/consume"))
        .header("X-Requested-With", "wick")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 404);

    // Reveal page now reports unavailable.
    let reveal_after = client.get(format!("{base}/s/{id}")).send().await.unwrap();
    assert_eq!(reveal_after.status(), 200);
    let html_after = reveal_after.text().await.unwrap();
    assert!(html_after.contains("gone") || html_after.contains("no longer available") || !html_after.contains("reveal-button"));
}

#[tokio::test]
async fn expired_secret_is_unreachable() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // ttl_secs = 0 is not one of the allowed choices in the real config, but the test
    // config exposes a 1-second choice so this test can observe expiry quickly without
    // relaxing validation in the handler itself.
    let create_res = client
        .post(format!("{base}/api/secrets"))
        .json(&sample_create_body(1))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), 200);
    let body: Value = create_res.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let consume_res = client
        .post(format!("{base}/api/secrets/{id}/consume"))
        .header("X-Requested-With", "wick")
        .send()
        .await
        .unwrap();
    assert_eq!(consume_res.status(), 404);
}

#[tokio::test]
async fn oversized_ciphertext_is_rejected() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // MAX_SECRET_BYTES is set to 1024 in spawn_app; send something bigger.
    let big = "a".repeat(4096);
    let body = json!({
        "ciphertext": base64url(&big),
        "nonce": base64url("123456789012"),
        "salt": null,
        "requires_passphrase": false,
        "ttl_secs": 300,
    });

    let res = client
        .post(format!("{base}/api/secrets"))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert!(
        res.status() == 413 || res.status() == 400,
        "expected 413 or 400, got {}",
        res.status()
    );
}

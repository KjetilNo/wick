use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{ConsumeResponse, CreateSecretRequest, CreateSecretResponse};
use crate::AppState;

#[derive(Template, WebTemplate)]
#[template(path = "create.html")]
pub struct CreateTemplate {
    pub ttl_choices: Vec<(&'static str, i64)>,
    pub max_bytes: usize,
}

#[derive(Template, WebTemplate)]
#[template(path = "reveal.html")]
pub struct RevealTemplate {
    pub id: String,
    pub available: bool,
    pub requires_passphrase: bool,
}

pub async fn create_page(State(state): State<AppState>) -> CreateTemplate {
    CreateTemplate {
        ttl_choices: state.config.ttl_choices_secs.clone(),
        max_bytes: state.config.max_secret_bytes,
    }
}

pub async fn healthz() -> &'static str {
    "ok"
}

#[derive(Template, WebTemplate)]
#[template(path = "notfound.html")]
pub struct NotFoundTemplate;

pub async fn fallback_404() -> (axum::http::StatusCode, NotFoundTemplate) {
    (axum::http::StatusCode::NOT_FOUND, NotFoundTemplate)
}

/// Generates a random, url-safe, unguessable secret id. 16 bytes (128 bits) of entropy --
/// plenty to make enumeration infeasible, short enough to paste comfortably into a URL.
fn generate_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn create_secret(
    State(state): State<AppState>,
    Json(req): Json<CreateSecretRequest>,
) -> AppResult<Json<CreateSecretResponse>> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&req.ciphertext)
        .map_err(|_| AppError::BadRequest("ciphertext is not valid base64url".into()))?;

    let nonce = URL_SAFE_NO_PAD
        .decode(&req.nonce)
        .map_err(|_| AppError::BadRequest("nonce is not valid base64url".into()))?;

    let salt = match &req.salt {
        Some(s) => Some(
            URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|_| AppError::BadRequest("salt is not valid base64url".into()))?,
        ),
        None => None,
    };

    if req.requires_passphrase && salt.is_none() {
        return Err(AppError::BadRequest(
            "salt is required when requires_passphrase is set".into(),
        ));
    }

    if ciphertext.len() > state.config.max_secret_bytes {
        return Err(AppError::PayloadTooLarge);
    }

    if ciphertext.is_empty() {
        return Err(AppError::BadRequest("ciphertext must not be empty".into()));
    }

    // GCM nonces are always 96 bits in this scheme.
    if nonce.len() != 12 {
        return Err(AppError::BadRequest("nonce must be 12 bytes".into()));
    }

    let allowed_ttl = state
        .config
        .ttl_choices_secs
        .iter()
        .any(|(_, secs)| *secs == req.ttl_secs);
    if !allowed_ttl {
        return Err(AppError::BadRequest("ttl_secs is not one of the allowed choices".into()));
    }

    let id = generate_id();
    let created_at = db::now_secs();
    let expires_at = created_at + req.ttl_secs;

    db::insert_secret(
        &state.db,
        &id,
        &ciphertext,
        &nonce,
        salt.as_deref(),
        req.requires_passphrase,
        created_at,
        expires_at,
    )
    .await?;

    Ok(Json(CreateSecretResponse { id }))
}

/// Metadata-only page: tells the viewer whether a secret is there and whether it needs a
/// passphrase, but never the ciphertext. Clicking "Reveal" is what actually burns it, via
/// `consume_secret` below -- a plain GET here (e.g. a chat app unfurling the link) is inert.
pub async fn reveal_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<RevealTemplate> {
    let meta = db::get_secret_meta(&state.db, &id, db::now_secs()).await?;

    match meta {
        Some(meta) => Ok(RevealTemplate {
            id,
            available: true,
            requires_passphrase: meta.requires_passphrase,
        }),
        None => Ok(RevealTemplate {
            id,
            available: false,
            requires_passphrase: false,
        }),
    }
}

pub async fn consume_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<ConsumeResponse>> {
    // Plain HTML forms/img tags can never set custom headers, so this blocks a third party
    // from burning a secret via a cross-site auto-submitting form that only knows the id.
    let requested_by_client = headers
        .get("x-requested-with")
        .and_then(|v| v.to_str().ok())
        == Some("wick");
    if !requested_by_client {
        return Err(AppError::BadRequest("missing x-requested-with header".into()));
    }

    let consumed = db::consume_secret(&state.db, &id, db::now_secs())
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(ConsumeResponse {
        ciphertext: URL_SAFE_NO_PAD.encode(&consumed.ciphertext),
        nonce: URL_SAFE_NO_PAD.encode(&consumed.nonce),
        salt: consumed.salt.map(|s| URL_SAFE_NO_PAD.encode(&s)),
        requires_passphrase: consumed.requires_passphrase,
    }))
}

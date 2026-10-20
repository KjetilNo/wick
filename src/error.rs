use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Application-wide error type. Maps to the HTTP status codes the API contract promises:
/// 400 for malformed input, 404 for missing/expired/already-consumed secrets,
/// 413 for oversized payloads, 500 for anything unexpected.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("payload too large")]
    PayloadTooLarge,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Internal(anyhow::Error::new(err))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Never let the error body leak internals -- log server-side, return a generic message.
        if matches!(self, AppError::Internal(_)) {
            tracing::error!(error = %self, "internal error");
        }

        let body = match &self {
            AppError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        };

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

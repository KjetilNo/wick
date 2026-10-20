use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use rust_embed::RustEmbed;

/// Embeds everything under `static/` into the binary at compile time, so the whole app
/// (HTML templates are compiled in by askama; JS/CSS are embedded here) ships as one file.
#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

pub async fn serve(Path(path): Path<String>) -> impl IntoResponse {
    match Assets::get(&path) {
        Some(file) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                mime.as_ref().parse().unwrap_or_else(|_| "text/plain".parse().unwrap()),
            );
            // Static assets are content-addressed by their filename only, not hashed, so
            // keep caching conservative.
            headers.insert(header::CACHE_CONTROL, "public, max-age=300".parse().unwrap());
            (StatusCode::OK, headers, file.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

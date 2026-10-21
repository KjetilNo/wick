use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Applies to every response. Static assets are allowed to be cached; everything else
/// (the create/reveal pages and the JSON API) is marked `no-store` so secrets never end up
/// in a browser cache or an intermediate proxy.
pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let is_static = req.uri().path().starts_with("/static/");

    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );

    if !is_static {
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
    }

    res
}

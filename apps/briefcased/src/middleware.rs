use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use subtle::ConstantTimeEq;

pub async fn require_loopback(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !addr.ip().is_loopback() {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"code":"forbidden","message":"loopback_only"}"#,
            ))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }
    next.run(request).await
}

pub async fn require_auth(
    State(auth_token): State<String>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let authorized = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|presented| {
            let a = presented.as_bytes();
            let b = auth_token.as_bytes();
            a.ct_eq(b).into()
        })
        .unwrap_or(false);

    if !authorized {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"code":"unauthorized","message":"missing or invalid authorization"}"#,
            ))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    next.run(request).await
}

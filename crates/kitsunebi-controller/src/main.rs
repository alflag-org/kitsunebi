#![forbid(unsafe_code)]

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use kitsunebi_api::{ApiError, router};
use kitsunebi_controller::Controller;
use std::path::{Path, PathBuf};

async fn safe_static_file(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let root = tokio::fs::canonicalize(root).await.ok()?;
    let candidate = tokio::fs::canonicalize(candidate).await.ok()?;
    if !candidate.starts_with(root) {
        return None;
    }
    tokio::fs::metadata(&candidate)
        .await
        .ok()
        .filter(|metadata| metadata.is_file())?;
    Some(candidate)
}

fn static_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

async fn request_id(request: Request<Body>, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    if !response.headers().contains_key("x-request-id")
        && let Ok(value) = id.parse()
    {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

async fn static_or_not_found(root: PathBuf, req: Request<Body>) -> Response {
    if req.method() != Method::GET
        || req.uri().path() == "/api"
        || req.uri().path().starts_with("/api/")
    {
        return ApiError::NotFound.into_response();
    }
    let uri: Uri = req.uri().clone();
    let requested = uri.path().trim_start_matches('/');
    let path = if requested.is_empty() {
        root.join("index.html")
    } else {
        root.join(requested)
    };
    let safe =
        path.starts_with(&root) && !requested.split('/').any(|p| p == ".." || p.contains('\\'));
    let path = if safe {
        safe_static_file(&root, &path).await
    } else {
        None
    };
    let path = match path {
        Some(path) => path,
        None => match safe_static_file(&root, &root.join("index.html")).await {
            Some(path) => path,
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, static_content_type(&path))],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"status":"live"})),
    )
}

async fn ready(
    management: std::sync::Arc<kitsunebi_controller::MysqlManagement>,
) -> impl IntoResponse {
    match management.controller_database_ready().await {
        Ok(()) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "status": "ready",
                "checks": {"controller_database": "ready"},
            })),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "not_ready",
                "database": "unavailable"
            })),
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let config = kitsunebi_controller::Config::from_env()
        .map_err(|e| format!("configuration rejected: {e}"))?;
    tracing::info!(listen = %config.listen_addr, database = %config.redacted_database_url(), "starting Kitsunebi controller");
    let listen_addr = config.listen_addr.clone();
    let controller = Controller::build(config).await?;
    let management = controller.management.clone();
    let api = router(
        controller.management.clone(),
        controller.authenticator.clone(),
        controller.security.clone(),
    )?;
    let root = controller.config.web_static_root.clone();
    let api = api.fallback(move |req: Request<Body>| static_or_not_found(root.clone(), req));
    let app = Router::new()
        .route("/live", get(live))
        .route("/ready", get(move || ready(management.clone())))
        .fallback_service(api)
        .layer(middleware::from_fn(request_id));
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(kitsunebi_controller::shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[tokio::test]
    async fn static_fallback_serves_assets_but_never_api_paths() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("kitsunebi-controller-static-{suffix}"));
        fs::create_dir_all(&root).expect("create test static root");
        fs::write(root.join("index.html"), "spa").expect("write test index");
        fs::write(root.join("app.js"), "asset").expect("write test asset");
        #[cfg(unix)]
        let outside = {
            use std::os::unix::fs::symlink;
            let outside =
                std::env::temp_dir().join(format!("kitsunebi-controller-static-outside-{suffix}"));
            fs::create_dir_all(&outside).expect("create outside root");
            fs::write(outside.join("secret.txt"), "outside").expect("write outside file");
            symlink(outside.join("secret.txt"), root.join("escape.txt"))
                .expect("create escape symlink");
            outside
        };

        let asset = static_or_not_found(
            root.clone(),
            Request::builder()
                .uri("/app.js")
                .body(Body::empty())
                .expect("asset request"),
        )
        .await;
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            to_bytes(asset.into_body(), 64).await.unwrap().as_ref(),
            b"asset"
        );

        let api = static_or_not_found(
            root.clone(),
            Request::builder()
                .uri("/api/unknown")
                .body(Body::empty())
                .expect("api request"),
        )
        .await;
        assert_eq!(api.status(), StatusCode::NOT_FOUND);
        assert!(
            String::from_utf8_lossy(&to_bytes(api.into_body(), 128).await.unwrap())
                .contains("not_found")
        );

        let api_root = static_or_not_found(
            root.clone(),
            Request::builder()
                .uri("/api")
                .body(Body::empty())
                .expect("api root request"),
        )
        .await;
        assert_eq!(api_root.status(), StatusCode::NOT_FOUND);

        #[cfg(unix)]
        {
            let escaped = static_or_not_found(
                root.clone(),
                Request::builder()
                    .uri("/escape.txt")
                    .body(Body::empty())
                    .expect("symlink request"),
            )
            .await;
            assert_eq!(escaped.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(escaped.into_body(), 64).await.unwrap().as_ref(),
                b"spa"
            );
            fs::remove_dir_all(outside).expect("remove outside root");
        }

        let _ = fs::remove_dir_all(root);
    }
}

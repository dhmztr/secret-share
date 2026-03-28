use axum::{
    Router,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get,post},
};
use sqlx::PgPool;
mod apis;
use apis::*;
use crypto::Envelope;
use db::connect;
use frontend::{App, FAVICON, STYLES};
use leptos::prelude::*;

const ADDR: &str = "0.0.0.0:8080";

fn shell() -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <meta name="description" content="Securely share secrets with self-destructing links" />
                <title>"SecretShare — Create a secure link"</title>
                <link rel="preconnect" href="https://fonts.googleapis.com" />
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
                <link rel="icon" href="/favicon.svg" />
                <link rel="stylesheet" href="/style.css" />
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

async fn style() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("text/css; charset=utf-8"))],
        STYLES,
    )
}

async fn favicon() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("image/svg+xml; charset=utf-8"))],
        FAVICON,
    )
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[tokio::main]
async fn main() {
    let connection = connect("REDACTED_USER","REDACTED_PASSWORD",5432,"REDACTED_HOST","secret_share").await.unwrap();
    let _ = any_spawner::Executor::init_tokio();
    let app = make_router().await;

    let listener = tokio::net::TcpListener::bind(ADDR).await.unwrap();
    println!("Serving on {ADDR}");
    axum::serve(listener, app).await.unwrap();
}

pub async fn make_router() -> Router {
    let pool= connect("REDACTED_USER","REDACTED_PASSWORD",5432,"REDACTED_HOST","secret_share").await.unwrap();
    Router::new()
        // --- API (MVP) ---
        .route("/api/secrets", post(encrypt_data))
        .route("/api/secrets/:id/fetch", post(fetch_decrypt))
        .route("/api/secrets/:id/meta", get(fetch_metadata))
        .route("/api/secrets/:id/burn", post(burn))
        // --- misc ---
        .route("/health", get(health))
        .route("/style.css", get(style))
        .route("/favicon.svg", get(favicon))
        // --- leptos app ---
        .fallback(leptos_axum::render_app_to_stream(shell))
        // IMPORTANT: wrzucamy pool do state
        .with_state(pool)
}

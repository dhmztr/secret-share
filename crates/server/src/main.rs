#![recursion_limit = "256"]

use axum::{
    extract::State,
    Router,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get, post},
};
use sqlx::{Pool,Postgres};
use leptos::prelude::*;
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use redis::aio::MultiplexedConnection;
#[derive(Clone)]
pub struct AppState {
    pub redis:MultiplexedConnection,
    pub postgres: Pool<Postgres>,
}
impl AppState {
    pub fn new(redis:MultiplexedConnection,postgres:Pool<Postgres>) -> Self {
        AppState {
            redis,
            postgres
        }

    }
}
mod apis;
use apis::*;
use db::{connect_postgres,connect_redis};
use frontend::{App, FAVICON, STYLES};

// ---------------------------------------------------------------------------
// HTML shell
// ---------------------------------------------------------------------------
//
// The script tag loads the WASM bundle produced by cargo-leptos and calls the
// `hydrate()` entry-point exported by the frontend crate.  cargo-leptos sets
// LEPTOS_SITE_PKG_DIR and LEPTOS_OUTPUT_NAME at runtime so the paths are
// always correct regardless of build configuration.

fn shell() -> impl IntoView {
    let pkg = std::env::var("LEPTOS_SITE_PKG_DIR").unwrap_or_else(|_| "pkg".to_string());
    let name = std::env::var("LEPTOS_OUTPUT_NAME").unwrap_or_else(|_| "frontend".to_string());

    // Build the JS script as a raw string. Note we escape all JS braces with
    // double braces {{ }} so format! treats them as literal braces, and we use
    // {} placeholders to interpolate `pkg` and `name`.
    let script_content = format!(
        r#"
        console.log("Loading WASM...");
        import init, {{ hydrate }} from "/{}/{}.js";
        init("/{}/{}.wasm")
            .then(() => {{
                console.log("WASM loaded successfully.");
                hydrate();
            }})
            .catch(err => {{
                console.error("WASM initialization failed:", err);
            }});
        "#,
        pkg, name, pkg, name
    );

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <meta name="description"
                    content="Securely share secrets with self-destructing links"/>
                <title>"SecretShare — share a secret"</title>

                <link rel="preconnect" href="https://fonts.googleapis.com"/>
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous"/>
                <link
                    href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"
                    rel="stylesheet"
                />
                <link rel="icon"       href="/favicon.svg"/>
                <link rel="stylesheet" href="/style.css"/>

                // Inject the generated JS safely as the script's inner HTML
                <script type="module" inner_html=script_content></script>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}
// ---------------------------------------------------------------------------
// Misc handlers
// ---------------------------------------------------------------------------

async fn serve_style() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        STYLES,
    )
}

async fn serve_favicon() -> impl IntoResponse {
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml; charset=utf-8"),
        )],
        FAVICON,
    )
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub async fn make_router(pool: AppState) -> Router {
    // cargo-leptos sets these env vars before starting the server.
    // Defaults are used when running `cargo run` directly (non-cargo-leptos).
    let site_root = std::env::var("LEPTOS_SITE_ROOT").unwrap_or_else(|_| "target/site".to_string());
    let pkg_dir = std::env::var("LEPTOS_SITE_PKG_DIR").unwrap_or_else(|_| "pkg".to_string());

    // Absolute path to the directory that holds frontend.js / frontend_bg.wasm.
    let pkg_path = std::path::Path::new(&site_root).join(&pkg_dir);

    Router::new()
        // ── REST API ─────────────────────────────────────────────────────────
        .route("/api/secrets", post(encrypt_data))
        .route("/api/secrets/{id}/fetch", post(fetch_decrypt))
        .route("/api/secrets/{id}/meta", get(fetch_metadata))
        .route("/api/secrets/{id}/burn", post(burn))
        .route("/api/login",post(login))
        .route("/api/register",post(register))
        // ── Static assets ────────────────────────────────────────────────────
        .route("/health", get(health))
        .route("/style.css", get(serve_style))
        .route("/favicon.svg", get(serve_favicon))
        // Serve the WASM bundle built by cargo-leptos at /pkg/…
        .nest_service("/pkg", ServeDir::new(&pkg_path))
        // ── Leptos SSR ───────────────────────────────────────────────────────
        // render_app_to_stream renders the Leptos app for every unmatched
        // request.  The Leptos Router component inside App() reads the URL
        // from the request context and renders the correct view server-side.
        .fallback(leptos_axum::render_app_to_stream(shell))
        // Axum state: only the pool; Leptos context is wired inside the
        // render_app_to_stream closure via Leptos's own machinery.
        .with_state(pool)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Bind address: cargo-leptos sets LEPTOS_SITE_ADDR from Leptos.toml.
    let addr: SocketAddr = std::env::var("LEPTOS_SITE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("LEPTOS_SITE_ADDR is not a valid socket address");

    let psql_pool = connect_postgres(
        "REDACTED_USER",
        "REDACTED_PASSWORD",
        5432,
        "REDACTED_HOST",
        "secret_share",
    )
    .await
    .expect("failed to connect to PostgreSQL");
    let redis_pool = connect_redis("redis;//REDACTED_HOST:6379").await.expect("Failed to connect to redis");
    let state = AppState::new(redis_pool,psql_pool);
    // Initialise the async executor that Leptos uses for SSR.
    let _ = any_spawner::Executor::init_tokio();

    let app = make_router(state).await;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    println!("Serving on {addr}");
    axum::serve(listener, app).await.unwrap();
}

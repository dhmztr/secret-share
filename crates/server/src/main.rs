#![recursion_limit = "256"]

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get, post},
};
use axum_governor::{
    GovernorConfigBuilder, GovernorLayer, Quota,
    extractor::SmartIp,
    nz,
};
use ipnet::IpNet;
use leptos::prelude::*;
use std::str::FromStr;
use redis::aio::MultiplexedConnection;
use sqlx::{Pool, Postgres};
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
#[derive(Clone)]
pub struct AppState {
    pub redis: MultiplexedConnection,
    pub postgres: Pool<Postgres>,
}
impl AppState {
    pub fn new(redis: MultiplexedConnection, postgres: Pool<Postgres>) -> Self {
        AppState { redis, postgres }
    }
}
mod apis;
use apis::*;
use db::{connect_postgres, connect_redis};
use frontend::{App, FAVICON, STYLES};

fn shell() -> impl IntoView {
    let pkg = std::env::var("LEPTOS_SITE_PKG_DIR").unwrap_or_else(|_| "pkg".to_string());
    let name = std::env::var("LEPTOS_OUTPUT_NAME").unwrap_or_else(|_| "frontend".to_string());

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

                <script type="module" inner_html=script_content></script>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

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

/// Configure SmartIp with trusted proxy CIDRs for header extraction.
/// Trusts loopback and private ranges since cloudflared reaches the app
/// over the docker network; these ranges are not internet-reachable.
fn smart_ip() -> SmartIp {
    let trusted = [
        "127.0.0.1/32",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    .iter()
    .map(|s| IpNet::from_str(s).unwrap())
    .collect::<Vec<_>>();
    SmartIp::new().with_trusted_proxies(trusted)
}

pub async fn make_router(pool: AppState) -> Router {
    let site_root = std::env::var("LEPTOS_SITE_ROOT").unwrap_or_else(|_| "target/site".to_string());
    let pkg_dir = std::env::var("LEPTOS_SITE_PKG_DIR").unwrap_or_else(|_| "pkg".to_string());

    let pkg_path = std::path::Path::new(&site_root).join(&pkg_dir);
    let register_api_ratelimit = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_hour(nz!(10u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for register api!");

    let register_api_ratelimit_2 = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_hour(nz!(10u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for register api!");

    let api_limit = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_second(nz!(50u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for register api!");

    let api_limit_2 = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_second(nz!(50u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for register api!");

    let api_limit_3 = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_second(nz!(50u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for register api!");

    let metadata_limit = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_second(nz!(5u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for metadata api!");

    let verify_limit = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_hour(nz!(20u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for verify api!");

    let resend_limit = GovernorConfigBuilder::default()
        .with_extractor(smart_ip())
        .expect_connect_info()
        .quota_default(Quota::requests_per_hour(nz!(5u32)))
        .finish()
        .expect("Failed to initialize ratelimiter for resend api!");

    Router::new()
        .route(
            "/api/secrets",
            post(encrypt_data).layer(GovernorLayer::new(api_limit)),
        )
        .route(
            "/api/secrets/{id}/fetch",
            post(fetch_decrypt).layer(GovernorLayer::new(api_limit_2)),
        )
        .route(
            "/api/secrets/{id}/meta",
            get(fetch_metadata).layer(GovernorLayer::new(metadata_limit)),
        )
        .route(
            "/api/secrets/{id}/burn",
            post(burn).layer(GovernorLayer::new(api_limit_3)),
        )
        .route(
            "/api/login",
            post(login).layer(GovernorLayer::new(register_api_ratelimit)),
        )
        .route(
            "/api/register",
            post(register).layer(GovernorLayer::new(register_api_ratelimit_2)),
        )
        .route("/api/verify", post(verify).layer(GovernorLayer::new(verify_limit)))
        .route("/api/resend", post(resend_code).layer(GovernorLayer::new(resend_limit)))
        .route("/health", get(health))
        .route("/style.css", get(serve_style))
        .route("/favicon.svg", get(serve_favicon))
        .nest_service("/pkg", ServeDir::new(&pkg_path))
        .fallback(leptos_axum::render_app_to_stream(shell))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ))
        .layer(DefaultBodyLimit::max(26 * 1024 * 1024))
        .with_state(pool)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let addr: SocketAddr = std::env::var("LEPTOS_SITE_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("LEPTOS_SITE_ADDR is not a valid socket address");

    let db_user = std::env::var("DB_USER").expect("DB_USER must be set");
    let db_password = std::env::var("DB_PASSWORD").expect("DB_PASSWORD must be set");
    let db_host = std::env::var("DB_HOST").expect("DB_HOST must be set");
    let db_port: u16 = std::env::var("DB_PORT")
        .unwrap_or_else(|_| "5432".to_string())
        .parse()
        .expect("DB_PORT must be a valid port number");
    let db_name = std::env::var("DB_NAME").expect("DB_NAME must be set");
    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");

    let psql_pool = connect_postgres(&db_user, &db_password, db_port, &db_host, &db_name)
        .await
        .expect("failed to connect to PostgreSQL");
    db::run_migrations(&psql_pool)
        .await
        .expect("failed to run startup migrations");
    let redis_pool = connect_redis(&redis_url)
        .await
        .expect("Failed to connect to redis");
    let state = AppState::new(redis_pool, psql_pool);

    if let Err(e) = auth::SmtpConfig::from_env() {
        eprintln!("WARNING: email disabled — {e}");
    }

    const QUOTA_SYNC_INTERVAL_SECS: u64 = 60;
    let sync_state = state.clone();
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(QUOTA_SYNC_INTERVAL_SECS));
        loop {
            tick.tick().await;
            if let Err(e) =
                db::redis_synchronize_quota((&sync_state.postgres, sync_state.redis.clone())).await
            {
                eprintln!("quota sync failed: {e}");
            }
        }
    });

    let _ = any_spawner::Executor::init_tokio();

    let app = make_router(state).await;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind listener");

    println!("Serving on {addr}");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
}

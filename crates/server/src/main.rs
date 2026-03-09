
use axum::{
    routing::get,
    Router,
};
use tower_http::services::{ServeDir,ServeFile};
#[tokio::main]
async fn main() {
    let frontend_service = ServeDir::new("../../frontend/build")
        .not_found_service("../../frontend/build/index.html");

    let app = Router::new().fallback_service(frontend_service);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener,app).await.unwrap();


}

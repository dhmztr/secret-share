
use axum::{
    routing::get,
    Router,
};
const ADDR: &str = "0.0.0.0:8080";
use tower_http::services::{ServeDir,ServeFile};
#[tokio::main]
async fn main() {
    let frontend_service = ServeDir::new("../../../frontend/build/")
        .fallback(ServeFile::new("../../../frontend/build/"));

    let app = Router::new().fallback_service(frontend_service);

    let listener = tokio::net::TcpListener::bind(ADDR).await.unwrap();
    println!("Serving on {ADDR}");
    axum::serve(listener,app).await.unwrap();


}

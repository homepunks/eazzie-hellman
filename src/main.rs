use axum::{Router, routing::get};
use tokio::net;
use tower_http::trace::TraceLayer;
use eazzie_hellman::{ADDR, handlers::health_check};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http());

    let ln = net::TcpListener::bind(ADDR).await.unwrap();

    tracing::info!("[INFO] listening on http://{}", ADDR);
    axum::serve(ln, app).await.unwrap();
}

use crate::models::HealthResponse;
use axum::Json;

pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse { status: "OK" })
}

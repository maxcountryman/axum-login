use axum::extract::State;
use axum::response::IntoResponse;
use axum::{routing::get, Router};
use http::StatusCode;

use crate::backend::AppState;
use crate::store::Store;

pub fn router() -> Router<AppState> {
    Router::new().route("/nonce", get(get_nonce))
}

async fn get_nonce(State(state): State<AppState>) -> impl IntoResponse {
    let nonce = siwe::generate_nonce();

    // Store nonce in database
    let now = time::OffsetDateTime::now_utc();
    let expiry = now + time::Duration::minutes(5);

    if let Err(e) = state.create_nonce(nonce.as_str(), &now, &expiry).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    nonce.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::SqlitePool;
    use tower::ServiceExt;

    #[derive(Debug, sqlx::FromRow)]
    #[allow(unused)]
    struct NonceEntity {
        id: i64,
        nonce: String,
        created_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    }

    #[tokio::test]
    async fn test_get_nonce_success() {
        let db = SqlitePool::connect(":memory:").await.unwrap();

        let state = AppState { db: db.clone() };
        state.create_nonce_table().await.unwrap();

        let app = router().with_state(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let nonce = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map(|bytes| -> String { String::from_utf8(bytes.to_vec()).unwrap() })
            .unwrap();

        let (stored_nonce, created_at, expires_at): (
            String,
            time::OffsetDateTime,
            time::OffsetDateTime,
        ) = sqlx::query_as("SELECT nonce, created_at, expires_at FROM nonces WHERE nonce = ?")
            .bind(&nonce)
            .fetch_one(&db)
            .await
            .unwrap();

        assert_eq!(stored_nonce, nonce);

        let now = time::OffsetDateTime::now_utc();
        assert!(created_at < now);
        assert!(now < expires_at);
        assert!(now + time::Duration::minutes(5) >= expires_at);
    }
}

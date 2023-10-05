use std::net::SocketAddr;

use axum::{
    error_handling::HandleErrorLayer, middleware, response::IntoResponse, routing::get, BoxError,
    Router,
};
use axum_login::{require_auth, Auth, AuthState, SqliteUserStore};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use tower::ServiceBuilder;
use tower_sessions::{cookie::time::Duration, MemoryStore, SessionManagerLayer};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
struct MyUser {
    id: i64,
    name: String,
}

type MyAuth = Auth<MyUser, i64, SqliteUserStore>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session_store = MemoryStore::default();
    let session_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(SessionManagerLayer::new(session_store).with_max_age(Duration::days(1)));

    let pool = SqlitePool::connect("sqlite::memory:").await?;

    sqlx::query(r#"create table users (id integer primary key not null, name text not null)"#)
        .execute(&pool)
        .await?;
    sqlx::query(r#"insert into users (id, name) values (?, ?)"#)
        .bind(42)
        .bind("Ferris")
        .execute(&pool)
        .await?;

    let auth_state = AuthState::new(SqliteUserStore::new(pool));

    let app = Router::new()
        .route("/admin", get(admin_handler))
        .route_layer(middleware::from_fn_with_state(
            auth_state.clone(),
            require_auth,
        ))
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(session_service)
        .with_state(auth_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
async fn login_handler(mut auth: MyAuth) -> impl IntoResponse {
    auth.login(&42).await.unwrap();
    format!("Logged in as: {:?}", auth.user.unwrap().name)
}

async fn logout_handler(mut auth: MyAuth) -> impl IntoResponse {
    auth.logout();
    "Logged out."
}

async fn admin_handler(auth: MyAuth) -> impl IntoResponse {
    format!("Hi, {}!", auth.user.unwrap().name)
}

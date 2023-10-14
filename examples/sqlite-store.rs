use std::net::SocketAddr;

use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    BoxError, Router,
};
use axum_login::{require_authn, LoginManagerLayer, UserStore};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use time::Duration;
use tower::ServiceBuilder;
use tower_sessions::{MemoryStore, SessionManagerLayer};

#[derive(Debug, Clone)]
pub struct SqliteUserStore {
    pool: SqlitePool,
    query: String,
}

impl SqliteUserStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            query: String::from("select * from users where id = ?"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SqlxStoreError {
    /// A variant to map `sqlx` errors.
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
impl UserStore for SqliteUserStore {
    type User = User;
    type UserId = i64;
    type Error = SqlxStoreError;

    async fn load(&self, user_id: &Self::UserId) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as(&self.query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    async fn is_authenticated(&self, _user: &User) -> bool {
        true
    }

    async fn authentication_failure<B: Send>(&self, _req: Request<B>) -> Response {
        Redirect::to("/login").into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    name: String,
}

type Auth = axum_login::Auth<SqliteUserStore>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePool::connect("sqlite::memory:").await?;

    let session_store = MemoryStore::default();
    let user_store = SqliteUserStore::new(pool.clone());

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_max_age(Duration::days(1));

    let login_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(LoginManagerLayer::new(user_store, session_layer));

    // Set up example database.
    sqlx::query(r#"create table users (id integer primary key not null, name text not null)"#)
        .execute(&pool)
        .await?;
    sqlx::query(r#"insert into users (id, name) values (?, ?)"#)
        .bind(42)
        .bind("Ferris")
        .execute(&pool)
        .await?;

    let app = Router::new()
        .route("/admin", get(admin_handler))
        .route_layer(middleware::from_fn(require_authn::<SqliteUserStore, _>))
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(login_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn login_handler(mut auth: Auth) -> impl IntoResponse {
    auth.login(&42).await.unwrap();

    let user = auth.user.unwrap();
    format!("Logged in as: {}", user.name)
}

async fn logout_handler(mut auth: Auth) -> impl IntoResponse {
    auth.logout().unwrap();
    "Logged out."
}

async fn admin_handler(auth: Auth) -> impl IntoResponse {
    let user = auth.user.unwrap();
    format!("Hi, {}!", user.name)
}

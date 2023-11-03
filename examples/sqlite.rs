use std::net::SocketAddr;

use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    extract::Query,
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::get,
    BoxError, Router,
};
use axum_login::{require_authn, AccessController, LoginManagerLayer};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use time::Duration;
use tower::ServiceBuilder;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};

#[derive(Debug, Clone)]
pub struct UserBackend {
    pool: SqlitePool,
    query: String,
}

impl UserBackend {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            query: String::from("select * from users where id = ?"),
        }
    }
}

#[async_trait]
impl AccessController for UserBackend {
    type User = User;
    type UserId = i64;
    type Error = sqlx::Error;

    async fn load_user(&self, user_id: &Self::UserId) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as(&self.query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    async fn authn_failure<B: Send>(&self, req: Request<B>) -> Response {
        let uri_str = &req.uri().to_string();
        let next = urlencoding::encode(uri_str);
        Redirect::to(&format!("/login?next={}", next)).into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    name: String,
}

type LoginSession = axum_login::LoginSession<UserBackend>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Session layer.
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    // Login service.
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    let access_controller = UserBackend::new(pool.clone());
    let login_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(LoginManagerLayer::new(access_controller, session_layer));

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
        .route_layer(middleware::from_fn(require_authn::<UserBackend, _>))
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(login_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct NextUri {
    next: Option<String>,
}

async fn login_handler(
    mut login_session: LoginSession,
    Query(NextUri { next }): Query<NextUri>,
) -> impl IntoResponse {
    match login_session.login(&42).await {
        // User was found and set as logged in.
        Ok(Some(user)) => {
            if let Some(next) = next {
                Redirect::to(&next).into_response()
            } else {
                format!("Logged in as: {}", user.name).into_response()
            }
        }

        // The user didn't exist in our store.
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),

        // Our store failed for some reason.
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout_handler(mut login_session: LoginSession) -> impl IntoResponse {
    match login_session.logout() {
        Ok(_) => "Logged out.".into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn admin_handler(login_session: LoginSession, session: Session) -> impl IntoResponse {
    match login_session.user {
        Some(user) => {
            let mut visits: usize = session.get("visits").unwrap().unwrap_or_default();
            visits += 1;
            session.insert("visits", visits).unwrap();
            format!(
                "Hi, {}! You've visited this page {} times.",
                user.name, visits
            )
            .into_response()
        }

        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

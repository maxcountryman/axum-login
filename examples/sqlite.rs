use std::net::SocketAddr;

use askama::Template;
use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    BoxError, Form, Router,
};
use axum_login::{login_required, AuthBackend, AuthManagerLayer, AuthUser, UserId};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use time::Duration;
use tower::ServiceBuilder;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

#[derive(Debug, Clone)]
pub struct Backend {
    pool: SqlitePool,
}

impl Backend {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Deserialize)]
struct NextUri {
    next: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
    next: Option<String>,
}

#[async_trait]
impl AuthBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = sqlx::Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where username = ? and password = ?")
            .bind(creds.username)
            .bind(creds.password)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    username: String,
    password: String,
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> Vec<u8> {
        self.password.as_bytes().to_vec()
    }
}

type AuthSession = axum_login::AuthSession<Backend>;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    message: Option<String>,
    next: Option<String>,
}

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
}

async fn get_login_handler(Query(NextUri { next }): Query<NextUri>) -> LoginTemplate {
    LoginTemplate {
        message: None,
        next,
    }
}

async fn post_login_handler(
    mut auth_session: AuthSession,
    Form(creds): Form<Credentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(creds.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return LoginTemplate {
                message: Some("Invalid credentials.".to_string()),
                next: creds.next,
            }
            .into_response()
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if let Some(ref next) = creds.next {
        Redirect::to(next).into_response()
    } else {
        Redirect::to("/").into_response()
    }
}

async fn logout_handler(mut auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.logout() {
        Ok(_) => Redirect::to("/login").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn protected_handler(auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.user {
        Some(user) => ProtectedTemplate {
            username: &user.username,
        }
        .into_response(),

        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Session layer.
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    // Login service.
    let pool = SqlitePool::connect("sqlite:examples/example.db").await?;
    let backend = Backend::new(pool.clone());
    let auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(AuthManagerLayer::new(backend, session_layer));

    let app = Router::new()
        .route("/", get(protected_handler))
        .route_layer(login_required!(Backend, login_url = "/login"))
        .route("/login", post(post_login_handler))
        .route("/login", get(get_login_handler))
        .route("/logout", get(logout_handler))
        .layer(auth_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

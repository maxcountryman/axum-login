use std::{fmt::Debug, net::SocketAddr};

use askama::Template;
use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    BoxError, Form, Router,
};
use axum_login::{login_required, AuthManagerLayer, AuthUser, AuthnBackend, UserId};
use http::StatusCode;
use password_auth::verify_password;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use time::Duration;
use tower::ServiceBuilder;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

// Templates.

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    message: Option<String>,
    next: Option<String>,
}

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
}

// Extractors.

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

// This allows us to extract the authentication fields from forms. We use this
// to authenticate requests with the backend.
#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
    next: Option<String>,
}

// User and backend.

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    username: String,
    password: String,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// password hash.
impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password.as_bytes() // We use the password hash as the auth
                                 // hash--what this means
                                 // is when the user changes their password the
                                 // auth session becomes invalid.
    }
}

#[derive(Debug, Clone)]
pub struct Backend {
    pool: SqlitePool,
}

impl Backend {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = sqlx::Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user: Option<Self::User> = sqlx::query_as("select * from users where username = ? ")
            .bind(creds.username)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user.filter(|user| {
            verify_password(creds.password, &user.password)
                .ok()
                .is_some() // We're using password-based authentication--this
                           // works by comparing our form input with an argon2
                           // password hash.
        }))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }
}

// We use a type alias for convenience. Note that we've supplied our concrete
// backend here.
type AuthSession = axum_login::AuthSession<Backend>;

mod post_handlers {
    use super::*;

    // This is our POST log in handler.
    //
    // It uses our auth session and the form URL encoded credentials to authenticate
    // and log and user in.
    //
    // We've also implemented a basic scheme for displaying errors and redirecting
    // on success.
    pub async fn login(
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
}

mod get_handlers {
    use super::*;

    pub async fn login(Query(NextUrl { next }): Query<NextUrl>) -> LoginTemplate {
        LoginTemplate {
            message: None,
            next,
        }
    }

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout() {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    pub async fn protected(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user {
            Some(user) => ProtectedTemplate {
                username: &user.username,
            }
            .into_response(),

            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axum_login=debug,sqlx=warn,tower_http=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    // Session layer.
    //
    // This uses `tower-sessions` to establish a layer that will provide the session
    // as a request extension.
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    // Auth service.
    //
    // This combines the session layer with our backend to establish the auth
    // service which will provide the auth session as a request extension.
    let pool = SqlitePool::connect("sqlite:examples/example.db").await?;
    let backend = Backend::new(pool.clone());
    let auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(AuthManagerLayer::new(backend, session_layer));

    let app = Router::new()
        .route("/", get(get_handlers::protected))
        .route_layer(login_required!(Backend, login_url = "/login"))
        .route("/login", post(post_handlers::login))
        .route("/login", get(get_handlers::login))
        .route("/logout", get(get_handlers::logout))
        .layer(auth_service);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

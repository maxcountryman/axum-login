use std::{collections::HashSet, net::SocketAddr};

use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::get,
    BoxError, Router,
};
use axum_login::{
    login_required, permission_required, AuthBackend, AuthManagerLayer, AuthUser, UserId,
};
use http::{Request, StatusCode};
use hyper::Body;
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
impl AuthBackend for UserBackend {
    type User = User;
    type Credentials = Option<()>;
    type Permission = String;
    type Error = sqlx::Error;

    async fn authenticate<B: Send>(
        &self,
        _req: Request<B>,
        _creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // TODO: Use request to authenticate via a form.
        let user_id = 42;
        let user = sqlx::query_as(&self.query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as(&self.query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    async fn get_user_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let mut perms = HashSet::new();
        perms.insert("plebe".to_string());
        Ok(perms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    name: String,
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        42
    }

    fn session_auth_hash(&self) -> Vec<u8> {
        "bogus".as_bytes().to_vec()
    }
}

type AuthSession = axum_login::AuthSession<UserBackend>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Session layer.
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));

    // Login service.
    let pool = SqlitePool::connect("sqlite::memory:").await?;
    let user_backend = UserBackend::new(pool.clone());
    let auth_service = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|_: BoxError| async {
            StatusCode::BAD_REQUEST
        }))
        .layer(AuthManagerLayer::new(user_backend, session_layer));

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
        .route("/perms", get(admin_handler))
        .route_layer(permission_required!(
            UserBackend,
            login_url = "/login",
            "plebe".to_string()
        ))
        .route("/admin", get(admin_handler))
        .route_layer(login_required!(UserBackend, login_url = "/login"))
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(auth_service);

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
    mut auth_session: AuthSession,
    Query(NextUri { next }): Query<NextUri>,
    req: Request<Body>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(req, None).await {
        Ok(Some(user)) => user,

        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),

        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if let Some(next) = next {
        Redirect::to(&next).into_response()
    } else {
        format!("Logged in as: {}", user.name).into_response()
    }
}

async fn logout_handler(mut auth_session: AuthSession) -> impl IntoResponse {
    match auth_session.logout() {
        Ok(_) => "Logged out.".into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn admin_handler(auth_session: AuthSession, session: Session) -> impl IntoResponse {
    match auth_session.user {
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

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_login::{
    login_required,
    tower_sessions::{ExpiredDeletion, Expiry, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use serde_json::json;
use sqlx::SqlitePool;
use time::Duration;
use tokio::{signal, task::AbortHandle};
use tower_sessions::cookie::Key;
use tower_sessions_sqlx_store::SqliteStore;

use crate::{
    backend::{AuthSession, Backend, Credentials},
    store::Store,
    web::{nonce, state::AppState},
};

pub struct App {
    state: AppState,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db = SqlitePool::connect(":memory:").await?;
        // Create users table
        Ok(Self {
            state: AppState::new(db),
        })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let session_store = SqliteStore::new(self.state.db.clone());
        session_store.migrate().await?;
        self.state.initialize().await?;

        let deletion_task = {
            let seassion_store = session_store.clone();
            let state = self.state.clone();
            tokio::task::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                interval.tick().await; // The first tick completes immediately; skip.
                loop {
                    interval.tick().await;
                    let _ = seassion_store.delete_expired().await;
                    let _ = state.delete_expired_nonce().await;
                }
            })
        };

        let key = Key::generate();

        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_expiry(Expiry::OnInactivity(Duration::days(1)))
            .with_signed(key);

        let backend = Backend::new(self.state.db.clone());

        let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

        let app = Router::new()
            .route("/", get(self::handler::home))
            .route_layer(login_required!(Backend, login_url = "/login"))
            .route("/login", post(self::handler::login))
            .route("/logout", get(self::handler::logout))
            .route("/me", get(self::handler::me)) // Add verification endpoint
            .merge(nonce::router())
            .layer(auth_layer)
            .with_state(self.state);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(shutdown_signal(deletion_task.abort_handle()))
            .await?;

        let _ = deletion_task.await;

        Ok(())
    }
}

mod handler {
    use super::*;

    pub async fn home(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user().await {
            Some(user) => format!("Hello, {}! Address: {}", user.username, user.address),
            None => "You are not logged in.".to_string(),
        }
    }

    pub async fn login(
        auth_session: AuthSession,
        Json(creds): Json<Credentials>,
    ) -> impl IntoResponse {
        let user = match auth_session.authenticate(creds).await {
            Ok(Some(user)) => user,
            Ok(None) => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        if auth_session.login(&user).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        (StatusCode::OK, "Successfully logged in").into_response()
    }

    pub async fn logout(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => (StatusCode::OK, "Logged out").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }

    pub async fn me(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.user().await {
            Some(user) => Json(json!({
                "username": user.username,
                "address": user.address,
            }))
            .into_response(),
            None => (StatusCode::UNAUTHORIZED, "Not logged in").into_response(),
        }
    }
}

async fn shutdown_signal(deletion_task_abort_handle: AbortHandle) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { deletion_task_abort_handle.abort() },
        _ = terminate => { deletion_task_abort_handle.abort() },
    }
}

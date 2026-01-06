use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};
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
    backend::{AuthSession, Backend},
    store::Store,
    web::{auth, nonce},
};

pub struct App {
    backend: Backend,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db = SqlitePool::connect(":memory:").await?;
        // Create users table
        Ok(Self {
            backend: Backend::new(db),
        })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        let session_store = SqliteStore::new(self.backend.state().db.clone());
        session_store.migrate().await?;

        self.backend.initialize().await?;
        let state = self.backend.state().clone();

        let deletion_task = {
            let seassion_store = session_store.clone();
            let state = state.clone();
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

        let auth_layer = AuthManagerLayerBuilder::new(self.backend, session_layer).build();

        let app = Router::new()
            .route("/me", get(self::handler::me)) // Add verification endpoint
            .route_layer(login_required!(Backend, login_url = "/login"))
            .route("/", get(self::handler::home))
            .merge(nonce::router())
            .merge(auth::router())
            .layer(auth_layer)
            .with_state(state);

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

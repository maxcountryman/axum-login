use std::error::Error;

use axum::{body::Body, Router};
use axum_login::{login_required, AuthManagerLayerBuilder};
use axum_messages::MessagesManagerLayer;
use http::{header::CONTENT_TYPE, Request};
use sqlx::SqlitePool;
use time::Duration;
use tower::ServiceExt;
use tower_sessions::{cookie::Key, Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;

use crate::{
    users::{Backend, Credentials},
    web::{auth, protected},
};

async fn setup_app(pool: SqlitePool) -> Result<Router, Box<dyn Error>> {
    let session_store = SqliteStore::new(pool.clone());
    session_store.migrate().await?;

    // Generate a cryptographic key to sign the session cookie.
    let key = Key::generate();

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(1)))
        .with_signed(key);
    let backend = Backend::new(pool);
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
    let app = protected::router()
        .route_layer(login_required!(Backend, login_url = "/login"))
        .merge(auth::router())
        .layer(MessagesManagerLayer)
        .layer(auth_layer);

    Ok(app)
}

#[sqlx::test]
async fn test_login_logout(pool: SqlitePool) {
    let app = setup_app(pool).await.unwrap();

    let login_request = {
        let credentials = Credentials {
            username: "ferris".to_string(),
            password: "hunter42".to_string(),
            next: None,
        };
        // todo: unclear how to instatiate or add to request; no tests in axum-messages
        // let messages: Messages;
        let credentials = serde_urlencoded::to_string(credentials).unwrap();

        Request::builder()
            .uri("/login")
            .method("POST")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            // todo: where do I put messages in the request?
            .body(credentials)
            .unwrap()
    };
    let login_response = app.clone().oneshot(login_request).await.unwrap();
    dbg!(&login_response);
    assert!(login_response.status().is_redirection());

    // todo: how to verify that the user is logged in?

    // why is logout a get request instead of a post in the example?
    let logout_request = Request::builder()
        .uri("/logout")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let logout_response = app.clone().oneshot(logout_request).await.unwrap();
    dbg!(&logout_response);
    assert!(logout_response.status().is_redirection());
}

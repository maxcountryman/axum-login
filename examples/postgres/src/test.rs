use std::error::Error;

use axum::{body::Body, Router};
use axum_login::{login_required, AuthManagerLayerBuilder};
use axum_messages::MessagesManagerLayer;
use http::{header::CONTENT_TYPE, Request};
use sqlx::{FromRow, PgPool};
use time::Duration;
use tower::ServiceExt;
use tower_sessions::{cookie::Key, Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;

use crate::{
    users::{Backend, Credentials, User},
    web::{auth, protected},
};

async fn setup_app(pool: PgPool) -> Result<Router, Box<dyn Error>> {
    let session_store = PostgresStore::new(pool.clone());
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
async fn test_db(pool: PgPool) {
    let mut conn = pool.acquire().await.unwrap();

    let users = sqlx::query("SELECT * FROM users where username = $1")
        .bind("ferris")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let ferris: User = User::from_row(&users).unwrap();
    assert!(ferris.username == "ferris");
}

#[sqlx::test]
async fn test_login_logout(pool: PgPool) {
    let app = setup_app(pool).await.unwrap();

    let login_request = {
        let credentials = Credentials {
            username: "ferris".to_string(),
            password: "hunter42".to_string(),
            next: None,
        };
        let credentials = serde_urlencoded::to_string(credentials).unwrap();

        Request::builder()
            .uri("/login")
            .method("POST")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(credentials)
            .unwrap()
    };
    let login_response = app.clone().oneshot(login_request).await.unwrap();
    dbg!(&login_response);
    // todo(failing): can't connect to db?
    // See
    assert!(login_response.status().is_redirection());

    let logout_request = Request::builder()
        .uri("/logout")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let logout_response = app.clone().oneshot(logout_request).await.unwrap();
    dbg!(&logout_response);
    assert!(logout_response.status().is_redirection());
}

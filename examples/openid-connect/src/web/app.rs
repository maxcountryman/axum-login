use std::env;

use axum_login::{
    login_required,
    tower_sessions::{cookie::SameSite, Expiry, MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use sqlx::SqlitePool;
use time::Duration;

use crate::{
    users::Backend,
    web::{auth, oauth, protected},
};

pub struct App {
    db: SqlitePool,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv()?;

        let db = SqlitePool::connect(":memory:").await?;
        sqlx::migrate!().run(&db).await?;

        Ok(Self { db })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
            .with_expiry(Expiry::OnInactivity(Duration::days(1)));

        let client_id = env::var("CLIENT_ID")
            .map(ClientId::new)
            .expect("CLIENT_ID should be provided.");
        let client_secret = env::var("CLIENT_SECRET").map(ClientSecret::new).ok();
        let issuer_url = env::var("ISSUER_URL")
            .map(IssuerUrl::new)
            .expect("ISSUER_URL should be provided")
            .expect("ISSUER_URL should be in a valid format");

        let redirect_url = env::var("REDIRECT_URL")
            .map(RedirectUrl::new)
            .expect("REDIRECT_URL should be provided")
            .expect("REDIRECT_URL should be a valid URL");

        // Auth service.
        //
        // This combines the session layer with our backend to establish the auth
        // service which will provide the auth session as a request extension.
        let backend = Backend::new(self.db, client_id, client_secret, issuer_url, redirect_url);
        let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

        let app = protected::router()
            .route_layer(login_required!(Backend, login_url = "/login"))
            .merge(auth::router())
            .merge(oauth::router())
            .layer(auth_layer);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app.into_make_service()).await?;

        Ok(())
    }
}

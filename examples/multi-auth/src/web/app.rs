use std::env;

use axum_login::{
    login_required,
    tower_sessions::{cookie::SameSite, Expiry, MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl};
use sqlx::SqlitePool;
use time::Duration;

use crate::{
    users::{Backend, BasicClientSet},
    web::{auth, oauth, protected},
};

pub struct App {
    db: SqlitePool,
    client: BasicClientSet,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv()?;

        let client_id = env::var("CLIENT_ID")
            .map(ClientId::new)
            .expect("CLIENT_ID should be provided.");
        let client_secret = env::var("CLIENT_SECRET")
            .map(ClientSecret::new)
            .expect("CLIENT_SECRET should be provided");

        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?;
        let client = BasicClient::new(client_id)
            .set_client_secret(client_secret)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);

        let db = SqlitePool::connect(":memory:").await?;
        sqlx::migrate!().run(&db).await?;

        Ok(Self { db, client })
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

        // Auth service.
        //
        // This combines the session layer with our backend to establish the auth
        // service which will provide the auth session as a request extension.
        let backend = Backend::new(self.db, self.client);
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

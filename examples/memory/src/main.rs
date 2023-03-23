//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-memory
//! ```

use std::{collections::HashMap, sync::Arc};

use axum::{response::IntoResponse, routing::get, Extension, Router};
use axum_login::{
    axum_sessions::{async_session::MemoryStore as SessionMemoryStore, SessionLayer},
    memory_store::MemoryStore as AuthMemoryStore,
    secrecy::SecretVec,
    AuthLayer, AuthUser, RequireAuthorizationLayer,
};
use rand::Rng;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct User {
    id: usize,
    password_hash: String,
    name: String,
}

impl User {
    fn get_rusty_user() -> Self {
        Self {
            id: 1,
            name: "Ferris the Crab".to_string(),
            password_hash: "password".to_string(),
        }
    }
}

impl AuthUser<usize> for User {
    fn get_id(&self) -> usize {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }
}

type AuthContext = axum_login::extractors::AuthContext<usize, User, AuthMemoryStore<usize, User>>;

#[tokio::main]
async fn main() {
    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = SessionMemoryStore::new();
    let session_layer = SessionLayer::new(session_store, &secret).with_secure(false);

    let store = Arc::new(RwLock::new(HashMap::default()));
    let user = User::get_rusty_user();

    store.write().await.insert(user.get_id(), user);

    let user_store = AuthMemoryStore::new(&store);
    let auth_layer = AuthLayer::new(user_store, &secret);

    async fn login_handler(mut auth: AuthContext) {
        auth.login(&User::get_rusty_user()).await.unwrap();
    }

    async fn logout_handler(mut auth: AuthContext) {
        dbg!("Logging out user: {}", &auth.current_user);
        auth.logout().await;
    }

    async fn protected_handler(Extension(user): Extension<User>) -> impl IntoResponse {
        format!("Logged in as: {}", user.name)
    }

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .route_layer(RequireAuthorizationLayer::<usize, User>::login())
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(auth_layer)
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

//! Run with
//!
//! ```not_rust
//! cd examples && cargo run -p example-simple-with-role
//! ```

use std::{collections::HashMap, sync::Arc};
use axum::{
    response::IntoResponse,
    routing::get,
    Extension, Router,
};
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
    token_hash: String,
    name: String,
}

#[derive(Debug, Clone)]
struct PasswordUser(User);

impl User {
    fn get_rusty_user() -> Self {
        Self {
            id: 1,
            name: "Ferris the Crab".to_string(),
            password_hash: "password".to_string(),
            token_hash: "token".to_string(),
        }
    }
}

impl AuthUser<usize> for PasswordUser {
    fn get_id(&self) -> usize {
        self.0.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.0.password_hash.clone().into())
    }
}

#[derive(Debug, Clone)]
struct TokenUser(User);

impl AuthUser<usize> for TokenUser {
    fn get_id(&self) -> usize {
        self.0.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.0.token_hash.clone().into())
    }
}

type PasswordAuthContext = axum_login::extractors::AuthContext<usize, PasswordUser, AuthMemoryStore<usize, PasswordUser>>;

type TokenAuthContext = axum_login::extractors::AuthContext<usize, TokenUser, AuthMemoryStore<usize, TokenUser>>;

#[tokio::main]
async fn main() {
    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = SessionMemoryStore::new();
    let session_layer = SessionLayer::new(session_store, &secret).with_secure(false);

    let password_store = Arc::new(RwLock::new(HashMap::default()));
    let token_store = Arc::new(RwLock::new(HashMap::default()));

    let user = User::get_rusty_user();

    password_store.write().await.insert(user.clone().id, PasswordUser(user.clone()));
    token_store.write().await.insert(user.clone().id, TokenUser(user.clone()));

    let password_user_store = AuthMemoryStore::new(&password_store);
    let token_user_store = AuthMemoryStore::new(&token_store);
    let password_auth_layer = AuthLayer::new(password_user_store, &secret);
    let token_auth_layer = AuthLayer::new(token_user_store, &secret);

    async fn password_login_handler(mut auth: PasswordAuthContext) {
        auth.login(&PasswordUser(User::get_rusty_user())).await.unwrap();
    }

    async fn token_login_handler(mut auth: TokenAuthContext) {
        auth.login(&TokenUser(User::get_rusty_user())).await.unwrap();
    }


    async fn password_logout_handler(mut auth: PasswordAuthContext) {
        dbg!("Logging out user: {}", &auth.current_user);
        auth.logout().await;
    }

    async fn token_logout_handler(mut auth: TokenAuthContext) {
        dbg!("Logging out user: {}", &auth.current_user);
        auth.logout().await;
    }

    async fn password_protected_handler(Extension(user): Extension<PasswordUser>) -> impl IntoResponse {
        format!("Password logged in as: {}", user.0.name)
    }

    async fn token_protected_handler(Extension(user): Extension<TokenUser>) -> impl IntoResponse {
        format!("Token logged in as: {}", user.0.name)
    }

    let token_routes = Router::new()
        .route("/token/protected", get(token_protected_handler))
        .route_layer(RequireAuthorizationLayer::<usize, TokenUser>::login())
        .route("/token/login", get(token_login_handler))
        .route("/token/logout", get(token_logout_handler))
        .layer(token_auth_layer);

    let password_routes = Router::new()
        .route("/password/protected", get(password_protected_handler))
        .route_layer(RequireAuthorizationLayer::<usize, PasswordUser>::login())
        .route("/password/login", get(password_login_handler))
        .route("/password/logout", get(password_logout_handler))
        .layer(password_auth_layer);

    let app = Router::new()
        .merge(password_routes)
        .merge(token_routes)
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

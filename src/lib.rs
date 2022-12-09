//! Session-based user authentication for Axum.
//!
//! This crate provides a Tower middleware which creates a generic interface
//! between authenticated sessions and arbitrary user types. With it, these
//! authentication workflows are made easy:
//!
//! 1. Logging users in,
//! 2. Logging users out,
//! 3. Accessing the current user within a route,
//! 4. Protecting access to a resource.
//!
//! User storage is decoupled from authentication: any storage engine for which
//! [`UserStore`](user_store::UserStore) is
//! implemented is supported. Likewise any user type which implements
//! [`AuthUser`] may be used.
//!
//! Sessions are provided via [`axum-sessions`](axum_sessions). The session
//! layer must be installed before the authentication layer as the session will
//! be used internally, i.e. to store the user's authentication state.
//!
//! # Users
//!
//! In order for your user type to interoperate with this crate, you'll need to
//! implement `AuthUser` for it. Generally this should be straightforward. The
//! crate assumes you can provide a stable identifier as well as password hash,
//! both in terms of `String`. In the case of the latter, the semantics of
//! re-authentication can be controlled: if this value changes, then the session
//! becomes invalidate and the user must re-authenticate.
//!
//! ## Roles
//!
//! Optionally an arbitrary `Role` type may be provided. This allows
//! applications to restrict route access based on a role a given user may
//! have. Roles may be any type so long as they implement `PartialOrd` and
//! `PartialEq`. The [`get_role`](AuthUser::get_role) method should be
//! used for retrieving the current role of a given user. See
//! [`login_with_role`](RequireAuthorizationLayer::login_with_role) for
//! role-based route protection.
//!
//! # Stores
//!
//! User stores for sqlx are provided when the requisite feature flag is given.
//! This allows applications which already leverage sqlx to make sure of these
//! backends for user authentication. As an example, Postgres backends can be
//! used via [`PostgresStore`](sqlx_store::PostgresStore).
//!
//! # Example
//!
//! Most applications will use this middleware via axum.
//!
//! Note that the below example makes use of memory-based stores for
//! demonstration purposes only: more likely an application would never use
//! these stores in practice except to enable uses cases like testing.
//!
//! ```rust,no_run
//! use std::{collections::HashMap, sync::Arc};
//!
//! use axum::{response::IntoResponse, routing::get, Extension, Router};
//! use axum_login::{
//!     axum_sessions::{async_session::MemoryStore as SessionMemoryStore, SessionLayer},
//!     extractors::AuthContext,
//!     memory_store::MemoryStore as AuthMemoryStore,
//!     secrecy::SecretVec,
//!     AuthLayer, AuthUser, RequireAuthorizationLayer,
//! };
//! use rand::Rng;
//! use tokio::sync::RwLock;
//!
//! #[derive(Debug, Clone)]
//! struct User {
//!     id: usize,
//!     name: String,
//!     password_hash: String,
//!     role: Role,
//! }
//!
//! #[derive(Debug, Clone, PartialEq, PartialOrd)]
//! enum Role {
//!     User,
//!     Admin,
//! }
//!
//! impl User {
//!     fn get_rusty_user() -> Self {
//!         Self {
//!             id: 1,
//!             name: "Ferris the Crab".to_string(),
//!             password_hash: "password".to_string(),
//!             role: Role::Admin,
//!         }
//!     }
//! }
//!
//! impl AuthUser<Role> for User {
//!     fn get_id(&self) -> String {
//!         format!("{}", self.id)
//!     }
//!
//!     fn get_password_hash(&self) -> SecretVec<u8> {
//!         SecretVec::new(self.password_hash.clone().into())
//!     }
//!
//!     fn get_role(&self) -> Option<Role> {
//!         Some(self.role.clone())
//!     }
//! }
//!
//! type Auth = AuthContext<User, AuthMemoryStore<User>, Role>;
//!
//! #[tokio::main]
//! async fn main() {
//!     let secret = rand::thread_rng().gen::<[u8; 64]>();
//!
//!     let session_store = SessionMemoryStore::new();
//!     let session_layer = SessionLayer::new(session_store, &secret);
//!
//!     let store = Arc::new(RwLock::new(HashMap::default()));
//!     let user = User::get_rusty_user();
//!
//!     store.write().await.insert(user.get_id(), user);
//!
//!     let user_store = AuthMemoryStore::new(&store);
//!     let auth_layer = AuthLayer::new(user_store, &secret);
//!
//!     async fn login_handler(mut auth: Auth) {
//!         auth.login(&User::get_rusty_user()).await.unwrap();
//!     }
//!
//!     async fn logout_handler(mut auth: Auth) {
//!         dbg!("Logging out user: {}", &auth.current_user);
//!         auth.logout().await;
//!     }
//!
//!     async fn protected_handler(Extension(user): Extension<User>) -> impl IntoResponse {
//!         format!("Logged in as: {}", user.name)
//!     }
//!
//!     async fn admin_handler(Extension(user): Extension<User>) -> impl IntoResponse {
//!         format!("Logged in as admin: {}", user.name)
//!     }
//!
//!     let app = Router::new()
//!         .route("/admin", get(admin_handler))
//!         .route_layer(RequireAuthorizationLayer::<User, Role>::login_with_role(
//!             Role::Admin..,
//!         ))
//!         .route("/", get(protected_handler))
//!         .route_layer(RequireAuthorizationLayer::<User, Role>::login())
//!         .route("/login", get(login_handler))
//!         .route("/logout", get(logout_handler))
//!         .layer(auth_layer)
//!         .layer(session_layer);
//!
//!     axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod auth;
mod auth_user;
pub mod extractors;
pub mod memory_store;

#[cfg(feature = "sqlx")]
mod sqlx_store;
mod user_store;
pub use auth::{AuthLayer, RequireAuthorizationLayer};
pub use auth_user::AuthUser;
pub use axum_sessions;
use eyre::Error;
pub use secrecy;
#[cfg(feature = "mssql")]
pub use sqlx_store::MssqlStore;
#[cfg(feature = "mysql")]
pub use sqlx_store::MySqlStore;
#[cfg(feature = "postgres")]
pub use sqlx_store::PostgresStore;
#[cfg(feature = "sqlite")]
pub use sqlx_store::SqliteStore;
#[cfg(feature = "sqlx")]
pub use sqlx_store::SqlxStore;
pub use user_store::UserStore;

pub(crate) type Result<T = ()> = std::result::Result<T, Error>;

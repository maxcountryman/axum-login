//! # Overview
//!
//! This crate provides user identification, authentication, and authorization
//! as a `tower` middleware for `axum`.
//!
//! It offers:
//!
//! - **User Identification, Authentication, and Authorization**: Leverage
//!   [`AuthSession`] to easily manage authentication and authorization. This is
//!   also an extractor, so it can be used directly in your `axum` handlers.
//! - **Support for Arbitrary Users and Backends**: Applications implement a
//!   couple of traits, [`AuthUser`] and [`AuthnBackend`], allowing for any user
//!   type and any user management backend. Your database? Yep. LDAP? Sure. An
//!   auth provider? You bet.
//! - **User and Group Permissions**: Authorization is supported via the
//!   [`AuthzBackend`] trait, which allows applications to define custom
//!   permissions. Both user and group permissions are supported.
//! - **Convenient Route Protection**: Middleware for protecting access to
//!   routes are provided via the [`login_required`] and [`permission_required`]
//!   macros. Or bring your own by using [`AuthSession`] directly with
//!   [`from_fn`](axum::middleware::from_fn).
//! - **Rock-solid Session Management**: Uses [`tower-sessions`](tower_sessions)
//!   for high-performing and ergonomic session management. *Look ma, no
//!   deadlocks!*
//!
//! # Usage
//!
//! Applications implement two traits, and optionally a third, to enable login
//! workflows: [`AuthUser`] and [`AuthnBackend`]. Respectively, these define a
//! minimal interface for arbitrary user types and an interface with an
//! arbitrary user management backend.
//!
//! ```rust
//! use std::collections::HashMap;
//!
//! use async_trait::async_trait;
//! use axum_login::{AuthUser, AuthnBackend, UserId};
//!
//! #[derive(Debug, Clone)]
//! struct User {
//!     id: i64,
//!     pw_hash: Vec<u8>,
//! }
//!
//! impl AuthUser for User {
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         self.id
//!     }
//!
//!     fn session_auth_hash(&self) -> &[u8] {
//!         &self.pw_hash
//!     }
//! }
//!
//! #[derive(Clone, Default)]
//! struct Backend {
//!     users: HashMap<i64, User>,
//! }
//!
//! #[derive(Clone)]
//! struct Credentials {
//!     user_id: i64,
//! }
//!
//! #[async_trait]
//! impl AuthnBackend for Backend {
//!     type User = User;
//!     type Credentials = Credentials;
//!     type Error = std::convert::Infallible;
//!
//!     async fn authenticate(
//!         &self,
//!         Credentials { user_id }: Self::Credentials,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(self.users.get(&user_id).cloned())
//!     }
//!
//!     async fn get_user(
//!         &self,
//!         user_id: &UserId<Self>,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(self.users.get(user_id).cloned())
//!     }
//! }
//! ```
//!
//! Here we've provided implementations for our own user type and a backend (in
//! this case, we use a `HashMap` only as a proxy for something like a
//! database). If we also wanted to support authorization, we could extend with
//! this an implementation of [`AuthzBackend`].
//!
//! It's worth covering a couple of these methods in a little more detail:
//!
//! - `session_auth_hash`, which is used to validate the session; in our example
//!   we use a user's password hash, which means changing passwords will
//!   invalidate the session.
//! - `get_user`, which is used to load the user from the backend into the
//!   session.
//!
//! Note that our example is not realistic and is meant only to provide an
//! illustration of the API. For instance, our implementation of `authenticate`
//! would likely use proper credentials, and not an ID, to positively identify
//! and authenticate a user in a real backend system.
//!
//! ## Writing handlers
//!
//! With the traits implemented, we can write `axum` handlers, leveraging
//! [`AuthSession`] to manage authentication and authorization workflows.
//! Because `AuthSession` is an extractor, we can use it directly in our
//! handlers.
//!
//! ```rust
//! # use std::collections::HashMap;
//! #
//! # use async_trait::async_trait;
//! # use axum_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # #[async_trait]
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use axum::{
//!     http::StatusCode,
//!     response::{IntoResponse, Redirect},
//!     Form,
//! };
//!
//! type AuthSession = axum_login::AuthSession<Backend>;
//!
//! async fn login(
//!     mut auth_session: AuthSession,
//!     Form(creds): Form<Credentials>,
//! ) -> impl IntoResponse {
//!     let user = match auth_session.authenticate(creds.clone()).await {
//!         Ok(Some(user)) => user,
//!         Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
//!         Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
//!     };
//!
//!     if auth_session.login(&user).await.is_err() {
//!         return StatusCode::INTERNAL_SERVER_ERROR.into_response();
//!     }
//!
//!     Redirect::to("/protected").into_response()
//! }
//! ```
//!
//! This handler uses a `Form` extractor to retrieve credentials and then uses
//! them to authenticate with our backend. When successful we get back a user
//! and can then log the user in. Such a workflow can be adapted to the specific
//! needs of an application.
//!
//! ## Protecting routes
//!
//! Access to routes can be controlled with [`login_required`] and
//! [`permission_required`]. These produce middleware which may be used directly
//! with application routes.
//!
//! ```rust
//! # use std::collections::HashMap;
//! #
//! # use async_trait::async_trait;
//! # use axum_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # #[async_trait]
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use axum::{routing::get, Router};
//! use axum_login::login_required;
//!
//! fn protected_routes() -> Router {
//!     Router::new()
//!         .route(
//!             "/protected",
//!             get(|| async { "Gotta be logged in to see me!" }),
//!         )
//!         .route_layer(login_required!(Backend, login_url = "/login"))
//! }
//! ```
//!
//! Routes defined in this way can be protected by the middleware, in this case
//! ensuring that a user is logged before accessing the resource. When a user is
//! not logged in, the user agent is redirected to the provided login URL.
//!
//! Likewise, [`permission_required`] can be used to require user or
//! group permissions in order to access the protected resource.
//!
//! ## Setting up an auth service
//!
//! In order to make use of this within our `axum` application, we establish a
//! `tower` service which provides a middleware that attaches `AuthSession` as a
//! request extension.
//!
//! ```rust,no_run
//! # use std::collections::HashMap;
//! #
//! # use async_trait::async_trait;
//! # use axum_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone, Default)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # #[async_trait]
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use axum::{
//!     routing::{get, post},
//!     Router,
//! };
//! use axum_login::{
//!     login_required,
//!     tower_sessions::{MemoryStore, SessionManagerLayer},
//!     AuthManagerLayerBuilder,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Session layer.
//!     let session_store = MemoryStore::default();
//!     let session_layer = SessionManagerLayer::new(session_store);
//!
//!     // Auth service.
//!     let backend = Backend::default();
//!     let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
//!
//!     let app = Router::new()
//!         .route("/protected", get(todo!()))
//!         .route_layer(login_required!(Backend, login_url = "/login"))
//!         .route("/login", post(todo!()))
//!         .route("/login", get(todo!()))
//!         .layer(auth_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app.into_make_service()).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## One more thing
//!
//! While this overview of the API aims to give you a sense of how the crate
//! works and how you might use it with your own applications, these snippets
//! are incomplete and as such it's recommended to review a comprehensive
//! implementation as well.
//!
//! A complete example can be found in [`examples/sqlite.rs`](https://github.com/maxcountryman/axum-login/blob/main/examples/sqlite).
#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_docs,
    missing_debug_implementations
)]
#![forbid(unsafe_code)]

pub use axum;
pub use backend::{AuthUser, AuthnBackend, AuthzBackend, UserId};
#[doc(hidden)]
pub use middleware::url_with_redirect_query;
pub use service::{AuthManager, AuthManagerLayer, AuthManagerLayerBuilder};
pub use session::{AuthSession, Error};
pub use tower_sessions;
pub use tracing;

mod backend;
mod extract;
mod middleware;
mod service;
mod session;

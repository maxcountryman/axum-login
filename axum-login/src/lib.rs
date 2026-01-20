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
//!   routes is available via the [`login_required`] and [`permission_required`]
//!   macros, and via the builder-based [`require`] module (feature
//!   `require-builder`). The builder is the long-term primary surface; macros
//!   are convenience wrappers over the same behavior. Or bring your own by
//!   using [`AuthSession`] directly with
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
//! # fn main() {}
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
//! # #[cfg(feature = "macros-middleware")]
//! use axum::{routing::get, Router};
//! # #[cfg(feature = "macros-middleware")]
//! use axum_login::login_required;
//!
//! # #[cfg(feature = "macros-middleware")]
//! fn protected_routes() -> Router {
//!     Router::new()
//!         .route(
//!             "/protected",
//!             get(|| async { "Gotta be logged in to see me!" }),
//!         )
//!         .route_layer(login_required!(Backend, login_url = "/login"))
//! }
//! # fn main() {}
//! ```
//!
//! Routes defined in this way can be protected by the middleware, in this case
//! ensuring that a user is logged before accessing the resource. When a user is
//! not logged in, the user agent is redirected to the provided login URL.
//!
//! Likewise, [`permission_required`] can be used to require user or
//! group permissions in order to access the protected resource.
//!
//! ## Builder-based middleware
//!
//! ```rust,no_run
//! use axum_login::{
//!     require::{RedirectHandler, Require},
//!     AuthUser, AuthnBackend, UserId,
//! };
//!
//! #[derive(Clone, Debug)]
//! struct User;
//!
//! impl AuthUser for User {
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         0
//!     }
//!
//!     fn session_auth_hash(&self) -> &[u8] {
//!         &[]
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct Backend;
//!
//! impl AuthnBackend for Backend {
//!     type User = User;
//!     type Credentials = ();
//!     type Error = std::convert::Infallible;
//!
//!     async fn authenticate(
//!         &self,
//!         _: Self::Credentials,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//!
//!     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//! }
//!
//! let require = Require::<Backend>::builder()
//!     .unauthenticated(RedirectHandler::new().login_url("/login"))
//!     .build();
//! ```
//!
//! Use `.decision(...)` for custom access logic; it receives the auth session
//! plus `Arc<state>` when you build with shared state.
//!
//! ## Behavior contract
//!
//! The middleware surfaces follow the same contract:
//!
//! - If the request is unauthenticated, the unauthenticated handler is used.
//! - If the request is authenticated but not authorized, the unauthorized
//!   handler is used.
//! - Redirect fallbacks preserve explicit redirect query parameters if already
//!   present and otherwise append the configured redirect field.
//! - Redirect construction errors return `500 Internal Server Error`.
//!
//! ## Feature flags
//!
//! - `require-builder`: Enables the builder-based `require` module.
//! - `macros-middleware`: Enables the macro middleware and depends on
//!   `require-builder`. This is enabled by default.
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
//! # #[cfg(feature = "macros-middleware")]
//! use axum::{
//!     routing::{get, post},
//!     Router,
//! };
//! # #[cfg(feature = "macros-middleware")]
//! use axum_login::{
//!     login_required,
//!     tower_sessions::{MemoryStore, SessionManagerLayer},
//!     AuthManagerLayerBuilder,
//! };
//!
//! # #[cfg(feature = "macros-middleware")]
//! async fn run() -> Result<(), Box<dyn std::error::Error>> {
//!     // Session layer.
//!     let session_store = MemoryStore::default();
//!     let session_layer = SessionManagerLayer::new(session_store);
//!
//!     // Auth service.
//!     let backend = Backend::default();
//!     let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
//!
//!     let app = Router::new()
//!         .route("/protected", get::<(), _, _>(todo!()))
//!         .route_layer(login_required!(Backend, login_url = "/login"))
//!         .route("/login", post::<(), _, _>(todo!()))
//!         .route("/login", get::<(), _, _>(todo!()))
//!         .layer(auth_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app.into_make_service()).await?;
//!
//!     Ok(())
//! }
//! # fn main() {}
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
pub use service::{AuthManager, AuthManagerLayer, AuthManagerLayerBuilder};
pub use session::{AuthSession, Error};
pub use tower_sessions;
pub use tracing;

mod backend;
mod extract;
mod service;
mod session;

#[cfg(feature = "require-builder")]
pub mod require;

#[cfg(any(feature = "macros-middleware", feature = "require-builder"))]
pub use redirect::url_with_redirect_query;
#[cfg(feature = "macros-middleware")]
mod middleware;
#[cfg(any(feature = "macros-middleware", feature = "require-builder"))]
mod redirect;

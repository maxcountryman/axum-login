//! Authentication requirement middleware for Axum.
//!
//! This module provides the [`Require`] type, which acts as a configurable
//! middleware layer for enforcing authentication and access control in Axum
//! applications. It uses a set of customizable predicate, changeable restrict
//! and fallback handlers behaviors to control access to routes based on
//! authentication.
//! ## Overview
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
//! use axum::{
//!     routing::{get, post},
//!     Router,
//! };
//! use axum_login::{
//!     require::{RedirectFallback, Require, SimplePredicate},
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
//!     // Permission control layer
//!     let require = Require::<TestBackend>::builder()
//!         .fallback(RedirectFallback::new().login_url("/login"))
//!         .build();
//!
//!     let app = Router::new()
//!         .route("/protected", get(todo!()))
//!         .route_layer(require)
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
mod builder;
mod handler;
mod predicate;
mod service;
mod tests;

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use axum::body::Body;
use tower_layer::Layer;

pub use self::{
    builder::RequireBuilder,
    handler::{DefaultFallback, DefaultRestrict, RedirectFallback, SimpleResponseFallback},
    predicate::{AsyncPredicate, DefaultPredicate, SimplePredicate},
    service::RequireService,
};
use crate::AuthnBackend;

//TODO: relax bounds
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A configurable authentication and access control layer.
///
/// The [`Require`] struct serves as the core component of the authentication
/// middleware. It determines whether a request satisfies an access predicate
/// and applies restriction or fallback logic when access is denied.
///
/// This type is typically constructed using the [`Require::builder`] or
/// [`Require::builder_with_state`] methods.
///
/// # Type Parameters
/// - `B`: The authentication backend implementing [`AuthnBackend`].
/// - `ST`: Shared state used by predicates or handlers.
/// - `T`: Request body type (defaults to [`Body`]).
/// - `Fb`: Fallback handler type (defaults to [`DefaultFallback`]).
/// - `Rs`: Restriction handler type (defaults to [`DefaultRestrict`]).
/// - `Pr`: Predicate type used to determine access (defaults to
///   [`DefaultPredicate`]).
#[must_use]
#[derive(Debug)]
pub struct Require<
    B,
    ST = (),
    T = Body,
    Fb = DefaultFallback,
    Rs = DefaultRestrict,
    Pr = DefaultPredicate<B, ST>,
> where
    Fb: Send + 'static,
    Rs: Send + 'static,
    Pr: Send + 'static,
    B: AuthnBackend,
    T: Send + 'static,
{
    /// The predicate that determines if access should be granted.
    pub predicate: Pr,
    /// The restriction response for when the predicate restricts access.
    pub restrict: Rs,
    /// The fallback response for missing authentication.
    pub fallback: Fb,
    /// Arbitrary user state available the predicate.
    pub state: ST,
    /// Internal marker to maintain type safety.
    _phantom: PhantomData<(B, fn() -> T)>, //Sync trick
}

impl<B, Fb, Rs, Pr, ST, T> Require<B, ST, T, Fb, Rs, Pr>
where
    B: AuthnBackend,
    Fb: Clone + Send + Sync + 'static,
    Rs: Clone + Send + Sync + 'static,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + std::marker::Send,
    T: std::marker::Send,
{
    /// Creates a new [`Require`] instance with the specified predicate,
    /// restriction, fallback, and state.
    pub fn new(predicate: Pr, restrict: Rs, fallback: Fb, state: ST) -> Self {
        Self {
            predicate,
            restrict,
            fallback,
            state,
            _phantom: PhantomData,
        }
    }
}

//umm, manual clone, because of Body
impl<B, Fb, Rs, ST, T, Pr> Clone for Require<B, ST, T, Fb, Rs, Pr>
where
    Fb: Clone + 'static + std::marker::Send,
    Rs: Clone + 'static + std::marker::Send,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + std::marker::Send,
    B: Clone + AuthnBackend,
    T: std::marker::Send,
{
    fn clone(&self) -> Self {
        Self {
            predicate: self.predicate.clone(),
            restrict: self.restrict.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            _phantom: PhantomData,
        }
    }
}
impl<B, T> Require<B, (), T>
where
    B: AuthnBackend,
    T: 'static + Send,
{
    /// Returns a builder for constructing a [`Require`] layer with an empty
    /// state.
    #[inline]
    pub fn builder(
    ) -> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ()>> {
        RequireBuilder::new()
    }
}

impl<B, ST, T> Require<B, ST, T>
where
    B: AuthnBackend,
    T: 'static + Send,
    ST: std::marker::Send + std::clone::Clone + std::marker::Sync,
    DefaultPredicate<B, ST>: AsyncPredicate<B, ST>,
{
    /// Returns a builder for constructing a [`Require`] layer with custom
    /// shared state.
    #[inline]
    pub fn builder_with_state(
        state: ST,
    ) -> RequireBuilder<B, ST, T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ST>> {
        RequireBuilder::new_with_state(state)
    }
}

impl<S, B, ST, T, Fb, Rs, Pr> Layer<S> for Require<B, ST, T, Fb, Rs, Pr>
where
    B: Clone + AuthnBackend + Send + Sync + 'static,
    Fb: Clone + Send + Sync + 'static,
    Rs: Clone + Send + Sync + 'static,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + Send + Sync + 'static,
    T: std::marker::Send + 'static,
{
    type Service = RequireService<S, B, ST, T, Fb, Rs, Pr>;

    #[doc(hidden)]
    /// Wraps the given service with the [`Require`] authentication layer.
    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            layer: self.clone(),
        }
    }
}

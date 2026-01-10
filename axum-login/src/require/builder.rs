//! Builder for creating [`Require`] authentication and authorization layers.
//!
//! This module provides the [`RequireBuilder`] type, a flexible and composable
//! API for defining how authentication and authorization checks are performed
//! in your Axum application.
//!
//! The builder stores predicates and handlers behind `Arc` to keep the public
//! type simple while still accepting concrete implementations.
//!
//! It allows you to define **decisions**, **unauthorized responses**, and
//! **unauthenticated responses**, making it easy to handle cases such as
//! - redirecting unauthenticated users to a login page,
//! - returning a `403 Forbidden` for users without permission,
//! - applying custom logic for access control checks.
//!
//! ## Concepts
//!
//! - **Decision**: Determines if a request is allowed to proceed. It receives
//!   the auth session and state (if any). It can allow, deny as unauthorized,
//!   or deny as unauthenticated.
//!
//! - **Unauthenticated**: Handles cases when there is *no authenticated user*
//!   (e.g., redirect to login page).
//!
//! - **Unauthorized**: Handles cases when there *is* an authenticated user, but
//!   the user is not authorized (e.g., return `403 Forbidden`).
//!
//! - **State**: Optional shared data accessible by predicates. The state is
//!   stored once and provided as `Arc<ST>` to avoid per-request cloning.
//!
//! ## Default Behavior
//!
//! If you don't customize anything, `RequireBuilder` will use:
//!
//! - [`DefaultAccess`] — allows all authenticated users.
//! - [`DefaultUnauthorized`] — returns a `403 Forbidden` response for
//!   unauthorized users.
//! - [`DefaultUnauthenticated`] — returns a `401 Unauthorized` response for
//!   unauthenticated
//!
//! ## Example
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

use std::sync::Arc;

use axum::body::Body;

use crate::{
    require::{
        handler::{DefaultUnauthenticated, DefaultUnauthorized, ResponseHandler},
        predicate::{DecisionPredicate, DefaultAccess},
        Require, RequireState,
    },
    AuthnBackend,
};

/// A builder for creating [`Require`] layers with authentication and
/// authorization requirements.
///
/// The `RequireBuilder` provides a fluent API for composing authentication
/// logic in your Axum application. Each call to a method like
/// [`decision`](#method.decision),
/// [`unauthenticated`](#method.unauthenticated),
/// or [`RequireBuilder::unauthorized`] returns a new builder with the specified
/// configuration.
///
/// For the default configuration, you can use the
/// [`crate::require::RequireBuilderLayer`] type alias for shorter type
/// signatures.
///
/// # Example
///
/// ```rust,no_run
/// use axum_login::{
///     require::{RedirectHandler, Require, RequireBuilder},
///     AuthUser, AuthnBackend, UserId,
/// };
///
/// #[derive(Clone, Debug)]
/// struct User;
///
/// impl AuthUser for User {
///     type Id = i64;
///
///     fn id(&self) -> Self::Id {
///         0
///     }
///
///     fn session_auth_hash(&self) -> &[u8] {
///         &[]
///     }
/// }
///
/// #[derive(Clone)]
/// struct Backend;
///
/// impl AuthnBackend for Backend {
///     type User = User;
///     type Credentials = ();
///     type Error = std::convert::Infallible;
///
///     async fn authenticate(
///         &self,
///         _: Self::Credentials,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
///
///     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
/// }
///
/// let require = Require::<Backend>::builder()
///     .unauthenticated(RedirectHandler::new().login_url("/login"))
///     .build();
/// # let _builder: RequireBuilder<Backend> = Require::builder();
/// ```
#[derive(Clone)]
pub struct RequireBuilder<B, ST = (), T = Body> {
    /// Decision predicate for the request.
    decision: Arc<dyn DecisionPredicate<B, ST>>,
    /// Handler for unauthorized users.
    unauthorized: Arc<dyn ResponseHandler<T>>,
    /// Handler for unauthenticated users.
    unauthenticated: Arc<dyn ResponseHandler<T>>,
    /// Shared state available to predicates and handlers.
    state: Arc<ST>,
}

impl<B, ST, T> std::fmt::Debug for RequireBuilder<B, ST, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequireBuilder")
            .field("decision", &"DecisionPredicate")
            .field("unauthorized", &"ResponseHandler")
            .field("unauthenticated", &"ResponseHandler")
            .field("state", &"Arc<ST>")
            .finish()
    }
}

impl<B, T> Default for RequireBuilder<B, (), T>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B, T> RequireBuilder<B, (), T>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    /// Creates a new `RequireBuilder` with the default configuration.
    ///
    /// The default:
    /// - [`DefaultAccess`] allows authenticated users and returns
    ///   `Unauthenticated` otherwise.
    /// - [`DefaultUnauthorized`] returns `403 Forbidden`.
    /// - [`DefaultUnauthenticated`] returns `401 Unauthorized`.
    pub fn new() -> Self {
        Self {
            decision: Arc::new(DefaultAccess::default()),
            unauthorized: Arc::new(DefaultUnauthorized),
            unauthenticated: Arc::new(DefaultUnauthenticated),
            state: Arc::new(()),
        }
    }
}

impl<B, ST, T> RequireBuilder<B, ST, T>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    /// Creates a new `RequireBuilder` with the given application state.
    pub fn new_with_state(state: ST) -> Self {
        Self {
            decision: Arc::new(DefaultAccess::default()),
            unauthorized: Arc::new(DefaultUnauthorized),
            unauthenticated: Arc::new(DefaultUnauthenticated),
            state: Arc::new(state),
        }
    }
}

impl<B, ST, T> RequireBuilder<B, ST, T>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    /// Sets a custom decision predicate.
    ///
    /// The predicate determines whether a request is permitted to proceed.
    /// It receives the auth session plus an `Arc<ST>` of the shared state.
    /// It runs for every request and has access to the auth session and
    /// request state.
    ///
    /// The predicate receives an owned [`AuthSession`](crate::AuthSession);
    /// keep this type cheap to clone (for example, by storing shared state in
    /// `Arc`).
    pub fn decision<Pr2>(self, new_predicate: Pr2) -> Self
    where
        Pr2: DecisionPredicate<B, ST> + 'static,
    {
        Self {
            decision: Arc::new(new_predicate),
            ..self
        }
    }

    /// Sets a custom handler for unauthenticated requests.
    ///
    /// This handler is used when a request requires authentication, but no user
    /// is logged in.
    pub fn unauthenticated<Uh2>(self, new_handler: Uh2) -> Self
    where
        Uh2: ResponseHandler<T> + 'static,
    {
        Self {
            unauthenticated: Arc::new(new_handler),
            ..self
        }
    }

    /// Sets a custom handler for unauthorized requests.
    ///
    /// This handler is used when a user is authenticated but lacks permission
    /// to access the requested resource.
    pub fn unauthorized<Un2>(self, new_handler: Un2) -> Self
    where
        Un2: ResponseHandler<T> + 'static,
    {
        Self {
            unauthorized: Arc::new(new_handler),
            ..self
        }
    }

    /// Builds the final [`Require`] layer.
    ///
    /// This method consumes the builder and produces the middleware that can be
    /// applied to an Axum `Router` or `Service`.
    pub fn build(self) -> Require<B, ST, T> {
        let inner = RequireState {
            decision: self.decision,
            unauthorized: self.unauthorized,
            unauthenticated: self.unauthenticated,
            state: self.state,
        };
        Require {
            inner: Arc::new(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{require::Decision, AuthSession, AuthUser};

    #[derive(Clone, Debug)]
    struct TestUser;

    impl AuthUser for TestUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            1
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Clone)]
    struct TestBackend;

    impl AuthnBackend for TestBackend {
        type User = TestUser;
        type Credentials = ();
        type Error = std::convert::Infallible;

        async fn authenticate(
            &self,
            _: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(TestUser))
        }

        async fn get_user(&self, _: &i64) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(TestUser))
        }
    }

    #[derive(Debug, PartialEq)]
    struct TestState(i32);

    #[test]
    fn builder_debug_includes_type() {
        let builder = RequireBuilder::<TestBackend>::new();
        let formatted = format!("{:?}", builder);

        assert!(formatted.contains("RequireBuilder"));
    }

    #[test]
    fn builder_with_state_sets_state() {
        let state = TestState(42);
        let builder = RequireBuilder::<TestBackend, TestState>::new_with_state(state);

        assert_eq!(*builder.state, TestState(42));
    }

    #[tokio::test]
    async fn builder_decision_override_is_used() {
        let builder =
            RequireBuilder::<TestBackend>::new().decision(|_, _| async { Decision::Unauthorized });
        let require = builder.build();

        let store = std::sync::Arc::new(tower_sessions::MemoryStore::default());
        let session = tower_sessions::Session::new(None, store, None);
        let auth_session = AuthSession::from_session(session, TestBackend, "axum-login.data")
            .await
            .unwrap();

        let decision = require
            .inner
            .decision
            .decide(auth_session, std::sync::Arc::clone(&require.inner.state))
            .await;

        assert_eq!(decision, Decision::Unauthorized);
    }
}

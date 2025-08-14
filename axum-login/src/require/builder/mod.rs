// --- The Builder

//TODO: create Require without state (nullable state)

use crate::require::builder::params::{Fallback, Predicate, Rstr};
use crate::require::{FallbackFn, PredicateStateFn, Require, RestrictFn};
use crate::{AuthnBackend, AuthzBackend};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use std::fmt::Debug;
use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;

mod params;
mod tests;

/// A builder for creating [`Require`] layers with authentication and authorization requirements.
///
/// This builder provides a fluent interface for configuring how requests should be handled
/// when they don't meet the specified authentication or authorization requirements.
///
/// # Type Parameters
///
/// * `B` - The authentication backend type that implements [`AuthnBackend`]
/// * `ST` - The state type passed to the predicate function (defaults to `()`)
/// * `T` - The request body type (defaults to [`Body`])
/// ```
pub struct RequireBuilder<B: AuthnBackend, ST = (), T = Body> {
    /// Function for checking user permissions
    predicate: Option<PredicateStateFn<B, ST>>,
    /// Handler for user lacking permissions
    restrict: Option<RestrictFn<T>>,
    /// Handler for user authentication
    fallback: Option<FallbackFn<T>>,
    /// State to get values dynamically
    state: Option<ST>,
}

impl<B: AuthnBackend, ST: Clone, T: 'static + Send> Default for RequireBuilder<B, ST, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: AuthnBackend, ST: Clone, T: 'static + Send> RequireBuilder<B, ST, T> {
    /// Creates a new `RequireBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            predicate: None,
            restrict: None,
            fallback: None,
            state: None,
        }
    }

    /// Sets the custom predicate function for authorization checks.
    /// The predicate determines whether a request should be allowed to proceed.
    ///
    /// # Examples
    /// ```rust
    pub fn predicate(mut self, pred: Predicate<B, ST>) -> RequireBuilder<B, ST, T>
    where
        B: AuthnBackend + AuthzBackend + 'static,
        B::User: 'static,
        B::Permission: Clone + Debug,
        ST: Clone + Send + Sync + 'static,
    {
        self.predicate = Some(pred.into());
        self
    }

    /// Sets the fallback response for unauthenticated requests.
    /// When a request requires authentication but the user is not authenticated,
    /// the fallback response is used.
    pub fn fallback(mut self, func: Fallback<T>) -> Self {
        self.fallback = Some(func.into());
        self
    }

    /// Sets the restriction response for unauthorized requests.
    /// When a request fails authorization but the user is authenticated,
    /// the restriction response is used instead of redirecting.
    pub fn on_restrict(mut self, func: Rstr<T>) -> Self
    where
        T: Send + 'static,
    {
        self.restrict = Some(func.into());
        self
    }

    /// Sets the state value passed to the predicate function.
    pub fn state(mut self, state: ST) -> Self {
        self.state = Some(state);
        self
    }
    fn default_fallback() -> FallbackFn<T> {
        Arc::new(|_req| {
            Box::pin(async {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("Unauthorized".into())
                    .unwrap()
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }

    fn default_restrict() -> RestrictFn<T> {
        Arc::new(|_req| {
            Box::pin(async {
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body("Forbidden".into())
                    .unwrap()
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }

    /// Always returns True
    fn default_predicat() -> PredicateStateFn<B, ST> {
        Arc::new(|_backend: B, _user: B::User, _state: ST| {
            Box::pin(ready(true)) as Pin<Box<dyn Future<Output = bool> + Send>>
        })
    }

    /// Build the resulting middleware
    pub fn build(self) -> Require<B, ST, T> {
        let predicate = self.predicate.unwrap_or_else(Self::default_predicat);

        let fallback = self.fallback.unwrap_or_else(Self::default_fallback);
        let perm_fallback = self.restrict.unwrap_or_else(Self::default_restrict);

        Require {
            predicate,
            restrict: perm_fallback,
            fallback,
            state: self
                .state
                .expect("State is required. Use .state() or contribute to library"),
            // _marker: PhantomData,
        }
    }
}

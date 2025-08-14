// --- The Builder

use crate::require::builder::params::{Predicate, Rstr};
use crate::require::fallback::{AsyncFallback, DefaultFallback};
use crate::require::{PredicateStateFn, Require, RestrictFn};
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
pub struct RequireBuilder<B, ST = (), T = Body, Fb = DefaultFallback>
where
    B: AuthnBackend,
    Fb: Send + 'static,
{
    /// Function for checking user permissions
    predicate: Option<PredicateStateFn<B, ST>>,
    /// Handler for user lacking permissions
    restrict: Option<RestrictFn<T>>,
    /// Handler for user authentication
    fallback: Fb,
    /// State to get values dynamically
    state: ST,
}

impl<B: AuthnBackend, T: 'static + Send> RequireBuilder<B, (), T, DefaultFallback> {
    /// Creates a new `RequireBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            predicate: None,
            restrict: None,
            fallback: DefaultFallback,
            state: (),
        }
    }
}

impl<B: AuthnBackend, ST, T: 'static + Send> RequireBuilder<B, ST, T, DefaultFallback> {
    /// Creates a new `RequireBuilder` with set state.
    pub fn new_with_state(state: ST) -> Self {
        Self {
            predicate: None,
            restrict: None,
            fallback: DefaultFallback,
            state,
        }
    }
}
impl<B: AuthnBackend, Fb, ST: Clone, T: 'static + Send> RequireBuilder<B, ST, T, Fb>
where
    Fb: AsyncFallback<T> + Clone + std::marker::Send + std::marker::Sync,
{
    /// Sets the custom predicate function for authorization checks.
    /// The predicate determines whether a request should be allowed to proceed.
    ///
    /// # Examples
    /// ```rust
    pub fn predicate(mut self, pred: Predicate<B, ST>) -> RequireBuilder<B, ST, T, Fb>
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
    pub fn fallback<Fb2: AsyncFallback<T> + Send>(
        self,
        new_fallback: Fb2,
    ) -> RequireBuilder<B, ST, T, Fb2> {
        RequireBuilder {
            predicate: self.predicate,
            restrict: self.restrict,
            fallback: new_fallback,
            state: self.state,
        }
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
    pub fn build(self) -> Require<B, ST, T, Fb> {
        let predicate = self.predicate.unwrap_or_else(Self::default_predicat);

        let perm_fallback = self.restrict.unwrap_or_else(Self::default_restrict);

        Require {
            predicate,
            restrict: perm_fallback,
            fallback: self.fallback,
            state: self.state,
            // _marker: PhantomData,
        }
    }
}

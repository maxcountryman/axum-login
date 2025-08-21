// --- The Builder

use crate::require::builder::params::Predicate;
use crate::require::handler::{AsyncFallbackHandler, DefaultFallback, DefaultRestrict};
use crate::require::{PredicateStateFn, Require};
use crate::{AuthnBackend, AuthzBackend};
use axum::body::Body;
use std::fmt::Debug;
use std::future::{ready, Future};
use std::marker::PhantomData;
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
pub struct RequireBuilder<B, ST = (), T = Body, Fb = DefaultFallback, Rs = DefaultRestrict>
where
    B: AuthnBackend,
{
    /// Function for checking user permissions
    predicate: Option<PredicateStateFn<B, ST>>,
    /// Handler for user lacking permissions
    restrict: Rs,
    /// Handler for user authentication
    fallback: Fb,
    /// State to get values dynamically
    state: ST,
    _phantom: PhantomData<T>,
}

impl<B, T> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict>
where
    B: AuthnBackend,
    T: 'static + Send,
{
    /// Creates a new `RequireBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            predicate: None,
            restrict: DefaultRestrict,
            fallback: DefaultFallback,
            state: (),
            _phantom: PhantomData,
        }
    }
}

impl<B: AuthnBackend, ST, T: 'static + Send>
    RequireBuilder<B, ST, T, DefaultFallback, DefaultRestrict>
{
    /// Creates a new `RequireBuilder` with set state.
    pub fn new_with_state(state: ST) -> Self {
        Self {
            predicate: None,
            restrict: DefaultRestrict,
            fallback: DefaultFallback,
            state,
            _phantom: PhantomData,
        }
    }
}
impl<B: AuthnBackend, Fb, ST: Clone, T: 'static + Send, Rs> RequireBuilder<B, ST, T, Fb, Rs>
where
    Fb: AsyncFallbackHandler<T> + Clone + std::marker::Send + std::marker::Sync,
    Rs: AsyncFallbackHandler<T> + Clone + std::marker::Send + std::marker::Sync,
{
    /// Sets the custom predicate function for authorization checks.
    /// The predicate determines whether a request should be allowed to proceed.
    ///
    /// # Examples
    /// ```rust
    pub fn predicate(mut self, pred: Predicate<B, ST>) -> RequireBuilder<B, ST, T, Fb, Rs>
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
    pub fn fallback<Fb2: AsyncFallbackHandler<T> + Send>(
        self,
        new_fallback: Fb2,
    ) -> RequireBuilder<B, ST, T, Fb2, Rs> {
        RequireBuilder {
            predicate: self.predicate,
            restrict: self.restrict,
            fallback: new_fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Sets the restriction response for unauthorized requests.
    /// When a request fails authorization but the user is authenticated,
    /// the restriction response is used.
    pub fn restrict<Rs2: AsyncFallbackHandler<T> + Send>(
        self,
        new_restrict: Rs2,
    ) -> RequireBuilder<B, ST, T, Fb, Rs2> {
        RequireBuilder {
            predicate: self.predicate,
            restrict: new_restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Always returns True
    fn default_predicat() -> PredicateStateFn<B, ST> {
        Arc::new(|_backend: B, _user: B::User, _state: ST| {
            Box::pin(ready(true)) as Pin<Box<dyn Future<Output = bool> + Send>>
        })
    }

    /// Build the resulting middleware
    pub fn build(self) -> Require<B, ST, T, Fb, Rs> {
        let predicate = self.predicate.unwrap_or_else(Self::default_predicat);

        Require {
            predicate,
            restrict: self.restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }
}

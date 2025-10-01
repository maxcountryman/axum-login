// --- The Builder

use crate::require::handler::{AsyncFallbackHandler, DefaultFallback, DefaultRestrict};
use crate::require::predicate::{DefaultPredicate, PredicateAsync};
use crate::require::Require;
use crate::AuthnBackend;
use axum::body::Body;
use std::marker::PhantomData;

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
pub struct RequireBuilder<
    B,
    ST = (),
    T = Body,
    Fb = DefaultFallback,
    Rs = DefaultRestrict,
    Pr = DefaultPredicate<B, ST>,
> {
    /// Function for checking user permissions
    predicate: Pr,
    /// Handler for user lacking permissions
    restrict: Rs,
    /// Handler for user authentication
    fallback: Fb,
    /// State to get values dynamically
    state: ST,
    _phantom: PhantomData<(T, B)>,
}

impl<B, T> Default for RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict>
where
    B: AuthnBackend,
    T: 'static + Send,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B, T> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ()>>
where
    B: AuthnBackend,
    T: 'static + Send,
{
    /// Creates a new `RequireBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            predicate: DefaultPredicate {
                _marker: PhantomData,
            },
            restrict: DefaultRestrict,
            fallback: DefaultFallback,
            state: (),
            _phantom: PhantomData,
        }
    }
}

impl<B, ST, T> RequireBuilder<B, ST, T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ST>>
where
    DefaultPredicate<B, ST>: PredicateAsync<B, ST>,
    B: AuthnBackend,
    ST: std::marker::Send + std::marker::Sync + std::clone::Clone,
    T: 'static + Send,
{
    /// Creates a new `RequireBuilder` with a set state.
    pub fn new_with_state(state: ST) -> Self {
        Self {
            predicate: DefaultPredicate {
                _marker: PhantomData,
            },
            restrict: DefaultRestrict,
            fallback: DefaultFallback,
            state,
            _phantom: PhantomData,
        }
    }
}

impl<B, ST, T, Fb, Rs, Pr> RequireBuilder<B, ST, T, Fb, Rs, Pr>
where
    B: AuthnBackend,
    T: 'static + Send,
    ST: Clone + std::marker::Send,
    Fb: AsyncFallbackHandler<T> + std::marker::Send + std::marker::Sync,
    Rs: AsyncFallbackHandler<T> + std::marker::Send + std::marker::Sync,
    Pr: PredicateAsync<B, ST> + std::marker::Send + std::marker::Sync,
{
    /// Sets the custom predicate function for authorization checks.
    /// The predicate determines whether a request should be allowed to proceed.
    ///
    /// # Examples
    /// ```rust
    pub fn predicate<Pr2>(self, new_predicate: Pr2) -> RequireBuilder<B, ST, T, Fb, Rs, Pr2>
    where
        Pr2: PredicateAsync<B, ST> + std::marker::Send + std::marker::Sync,
    {
        RequireBuilder {
            predicate: new_predicate,
            restrict: self.restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Sets the fallback response for unauthenticated requests.
    /// When a request requires authentication but the user is not authenticated,
    /// the fallback response is used.
    pub fn fallback<Fb2>(self, new_fallback: Fb2) -> RequireBuilder<B, ST, T, Fb2, Rs, Pr>
    where
        Fb2: AsyncFallbackHandler<T> + std::marker::Send + std::marker::Sync,
    {
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
    pub fn restrict<Rs2>(self, new_restrict: Rs2) -> RequireBuilder<B, ST, T, Fb, Rs2, Pr>
    where
        Rs2: AsyncFallbackHandler<T> + Clone + std::marker::Send + std::marker::Sync,
    {
        RequireBuilder {
            predicate: self.predicate,
            restrict: new_restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Build the resulting middleware
    pub fn build(self) -> Require<B, ST, T, Fb, Rs, Pr> {
        Require {
            predicate: self.predicate,
            restrict: self.restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }
}

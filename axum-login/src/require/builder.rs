//! Builder for creating [`Require`] authentication and authorization layers.
//!
//! This module provides the [`RequireBuilder`] type, a flexible and composable
//! API for defining how authentication and authorization checks are performed
//! in your Axum application.
//!
//! It allows you to define **predicates**, **restriction behavior**, and
//! **fallback responses**, making it easy to handle cases such as
//! - redirecting unauthenticated users to a login page,
//! - returning a `403 Forbidden` for users without permission,
//! - applying custom logic for access control checks.
//!
//! ## Concepts
//!
//! - **Predicate**: Determines if a request is allowed to proceed. It receives
//!   the Backend, User, and State (if any). If it returns `false`, the
//!   restriction handler is triggered.
//!
//! - **Fallback**: Handles cases when there is *no authenticated user* (e.g.,
//!   redirect to login page).
//!
//! - **Restrict**: Handles cases when there *is* an authenticated user, but the
//!   user is not authorized (e.g., return `403 Forbidden`).
//!
//! - **State**: Optional shared data accessible by predicate.
//!
//! ## Default Behavior
//!
//! If you don't customize anything, `RequireBuilder` will use:
//!
//! - [`DefaultPredicate`] — allows all authenticated users.
//! - [`DefaultRestrict`] — returns a `403 Forbidden` response for unauthorized
//!   users.
//! - [`DefaultFallback`] — returns a `401 Unauthorized` response for
//!   unauthenticated

use std::marker::PhantomData;

use axum::body::Body;

use crate::{
    require::{
        handler::{AsyncFallbackHandler, DefaultFallback, DefaultRestrict},
        predicate::{AsyncPredicate, DefaultPredicate},
        Require,
    },
    AuthnBackend,
};

/// A builder for creating [`Require`] layers with authentication and
/// authorization requirements.
///
/// The `RequireBuilder` provides a fluent API for composing authentication
/// logic in your Axum application. Each call to a method like
/// [`predicate`](#method.predicate), [`fallback`](#method.fallback), or
/// [`restrict`](#method.restrict) returns a new builder with the specified
/// configuration.
#[derive(Debug, Clone)]
pub struct RequireBuilder<
    B,
    ST = (),
    T = Body,
    Fb = DefaultFallback,
    Rs = DefaultRestrict,
    Pr = DefaultPredicate<B, ST>,
> {
    /// Function for checking user permissions.
    predicate: Pr,
    /// Handler for user lacking permissions.
    restrict: Rs,
    /// Handler for unauthenticated users.
    fallback: Fb,
    /// Shared state available to predicates and handlers.
    state: ST,
    /// Internal marker to maintain type safety.
    _phantom: PhantomData<(B, fn() -> T)>, //Sync trick
}

impl<B, T> Default for RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict>
where
    B: AuthnBackend,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<B, T> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ()>>
where
    B: AuthnBackend,
{
    /// Creates a new `RequireBuilder` with the default configuration.
    ///
    /// The default:
    /// - [`DefaultPredicate`] allows all authenticated users.
    /// - [`DefaultRestrict`] returns `403 Forbidden`.
    /// - [`DefaultFallback`] redirects unauthenticated users to `/signin`.
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
    DefaultPredicate<B, ST>: AsyncPredicate<B, ST>,
    B: AuthnBackend,
{
    /// Creates a new `RequireBuilder` with the given application state.
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
    ST: Clone,
    Fb: AsyncFallbackHandler<T>,
    Rs: AsyncFallbackHandler<T>,
    Pr: AsyncPredicate<B, ST>,
{
    /// Sets a custom authorization predicate.
    ///
    /// The predicate determines whether a request is permitted to proceed.
    /// It runs for every request and has access to the authenticated user and
    /// request data.
    pub fn predicate<Pr2>(self, new_predicate: Pr2) -> RequireBuilder<B, ST, T, Fb, Rs, Pr2>
    where
        Pr2: AsyncPredicate<B, ST>,
    {
        RequireBuilder {
            predicate: new_predicate,
            restrict: self.restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Sets a custom fallback handler for unauthenticated requests.
    ///
    /// This handler is used when a request requires authentication, but no user
    /// is logged in.
    pub fn fallback<Fb2>(self, new_fallback: Fb2) -> RequireBuilder<B, ST, T, Fb2, Rs, Pr>
    where
        Fb2: AsyncFallbackHandler<T>,
    {
        RequireBuilder {
            predicate: self.predicate,
            restrict: self.restrict,
            fallback: new_fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Sets a custom restriction handler for unauthorized requests.
    ///
    /// This handler is used when a user is authenticated but lacks permission
    /// to access the requested resource.
    pub fn restrict<Rs2>(self, new_restrict: Rs2) -> RequireBuilder<B, ST, T, Fb, Rs2, Pr>
    where
        Rs2: AsyncFallbackHandler<T>,
    {
        RequireBuilder {
            predicate: self.predicate,
            restrict: new_restrict,
            fallback: self.fallback,
            state: self.state,
            _phantom: PhantomData,
        }
    }

    /// Builds the final [`Require`] layer.
    ///
    /// This method consumes the builder and produces the middleware that can be
    /// applied to an Axum `Router` or `Service`.
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

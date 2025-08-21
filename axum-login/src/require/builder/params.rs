use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::require::PredicateStateFn;
use crate::{AuthnBackend, AuthzBackend};

/// Represents different types of predicates for authorization checks.
/// A predicate determines whether a user should be allowed access to a protected resource.
/// It can be either a custom function or a parameter-based check for specific permissions.
///
/// # Type Parameters
/// * `B` - The authorization backend type that implements [`AuthzBackend`]
/// * `ST` - The state type passed to the predicate function
#[derive(Clone)]
pub enum Predicate<B: AuthzBackend, ST> {
    /// A custom function that performs authorization logic.
    /// The function receives the backend, user, and state and returns whether
    /// the user should be authorized.
    Function(PredicateStateFn<B, ST>),

    /// Parameter-based authorization that checks for specific permissions.
    /// This variant automatically checks if the user has ALL the specified permissions.
    Params {
        /// The permissions required for access
        permissions: Vec<B::Permission>,
    },
}

impl<B, ST> fmt::Debug for Predicate<B, ST>
where
    B: AuthzBackend,
    B::Permission: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Predicate::Function(_) => f.debug_tuple("Function").field(&"<function>").finish(),
            Predicate::Params { permissions } => f
                .debug_struct("Params")
                .field("permissions", permissions)
                .finish(),
        }
    }
}

impl<B: AuthzBackend, ST> Predicate<B, ST> {
    /// Creates a predicate from a closure.
    /// # Parameters
    ///
    /// * `f` - A closure that takes the backend, user, and state, returning a future that resolves to a boolean
    pub fn from_closure<F, Fut>(f: F) -> Self
    where
        F: Fn(B, B::User, ST) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        Self::Function(Arc::new(move |b, usr, st| Box::pin(f(b, usr, st))))
    }
}

impl<B, ST> From<Predicate<B, ST>> for PredicateStateFn<B, ST>
where
    B: AuthnBackend + AuthzBackend + 'static,
    B::User: 'static,
    B::Permission: Clone + Debug,
    ST: Clone + Send + Sync + 'static,
{
    fn from(params: Predicate<B, ST>) -> Self {
        match params {
            Predicate::Function(f) => Arc::new(move |backend, user, state| {
                Box::pin(f(backend, user, state)) as Pin<Box<dyn Future<Output = bool> + Send>>
            }),

            Predicate::Params {
                permissions: req_perms,
                ..
            } => {
                //TODO: redundant
                let req_perms = req_perms.clone();
                Arc::new(move |backend: B, user: B::User, _state: ST| {
                    let req_perms = req_perms.clone();
                    Box::pin(async move {
                        let Ok(u_perms) = backend.get_user_permissions(&user).await else {
                            return false;
                        };
                        let allow = req_perms.iter().all(|perm| u_perms.contains(perm));
                        allow
                    })
                })
            }
        }
    }
}

use std::{
    collections::HashSet,
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    sync::Arc,
};

use crate::{require::BoxFuture, AuthSession, AuthnBackend, AuthzBackend};

/// The decision returned by a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allow the request to proceed.
    Allow,
    /// The request is unauthenticated.
    Unauthenticated,
    /// The request is authenticated but unauthorized.
    Unauthorized,
}

// Note: this takes owned values of backend and user to keep the async boundary
// simple for callers.

/// Trait for deciding access for a request.
///
/// This trait takes an owned [`AuthSession`] to keep async usage ergonomic.
/// Implementations should be cheap to share across requests, typically by
/// storing any internal data behind `Arc`.
pub trait DecisionPredicate<B: AuthnBackend, ST = ()>: Send + Sync {
    /// Decide whether a request is allowed.
    ///
    /// The predicate takes the auth session and the shared state as `Arc<ST>`.
    ///
    /// See [`RequireBuilder::decision`] for more details.
    ///
    /// [`RequireBuilder::decision`]: super::builder::RequireBuilder
    fn decide(&self, auth_session: AuthSession<B>, state: Arc<ST>) -> BoxFuture<'static, Decision>;
}

/// The default [`DecisionPredicate`] implementation used by [`super::Require`].
#[derive(Clone, Debug)]
pub struct DefaultDecision<B: AuthnBackend, ST> {
    _marker: PhantomData<(B, ST)>,
}

impl<B: AuthnBackend, ST> Default for DefaultDecision<B, ST> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<B, ST> DecisionPredicate<B, ST> for DefaultDecision<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    fn decide(&self, auth_session: AuthSession<B>, _state: Arc<ST>) -> BoxFuture<'static, Decision> {
        Box::pin(async move {
            if auth_session.user().await.is_some() {
                Decision::Allow
            } else {
                Decision::Unauthenticated
            }
        })
    }
}
impl<F, B, ST, Fut> DecisionPredicate<B, ST> for F
where
    F: Fn(AuthSession<B>, Arc<ST>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Decision> + Send + 'static,
    B: AuthnBackend + 'static,
    ST: Send + Sync + 'static,
{
    fn decide(&self, auth_session: AuthSession<B>, state: Arc<ST>) -> BoxFuture<'static, Decision> {
        Box::pin((self)(auth_session, state))
    }
}

/// Defines how permissions should be checked
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    /// User must have ANY of the specified permissions
    Any,
    /// User must have All the specified permissions
    All,
    /// User must have EXACTLY the specified permissions (no more, no less)
    Exact,
}

#[derive(Debug, Clone)]
/// A simple stateless predicate that checks if the user has a set of
/// permissions.
///
/// # Example
///
/// ```rust,no_run
/// use axum_login::require::{CheckMode, Require, PermissionsPredicate};
/// use axum_login::{AuthUser, AuthnBackend, AuthzBackend, UserId};
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
/// #[derive(Clone, Debug, Eq, PartialEq, Hash)]
/// struct Permission(&'static str);
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
///     async fn get_user(
///         &self,
///         _: &UserId<Self>,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
/// }
///
/// impl AuthzBackend for Backend {
///     type Permission = Permission;
/// }
///
/// let predicate = PermissionsPredicate::<Backend>::new()
///     .with_permissions([Permission("admin.read")])
///     .with_mode(CheckMode::All);
///
/// let require = Require::<Backend>::builder().decision(predicate).build();
/// ```
pub struct PermissionsPredicate<B: AuthzBackend + AuthnBackend> {
    pub(crate) _marker: PhantomData<B>,
    // PERF: could add a single permission variant
    permissions: Arc<HashSet<B::Permission>>,
    check_mode: CheckMode,
}

impl<B: AuthnBackend + AuthzBackend> Default for PermissionsPredicate<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: AuthnBackend + AuthzBackend> PermissionsPredicate<B> {
    /// Create a new predicate with a single permission and ALL check mode.
    pub fn new() -> Self {
        let permissions: HashSet<B::Permission> = HashSet::new();
        Self {
            _marker: PhantomData,
            permissions: Arc::new(permissions),
            check_mode: CheckMode::All,
        }
    }
    /// Set the check mode for this predicate.
    pub fn with_mode(mut self, mode: CheckMode) -> Self {
        self.check_mode = mode;
        self
    }

    /// Add permissions to the predicate.
    pub fn with_permissions<I, P>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<B::Permission>,
    {
        let permissions = permissions.into_iter().map(Into::into).collect();
        self.permissions = Arc::new(permissions);
        self
    }
}

impl<B, ST> DecisionPredicate<B, ST> for PermissionsPredicate<B>
where
    B: AuthnBackend + AuthzBackend + Send + Sync + 'static,
    B::Permission: Clone + Send + Sync,
    ST: Send + Sync + 'static,
{
    fn decide(&self, auth_session: AuthSession<B>, _state: Arc<ST>) -> BoxFuture<'static, Decision> {
        let required_permissions = Arc::clone(&self.permissions);
        let check_mode = self.check_mode;

        Box::pin(async move {
            let Some(user) = auth_session.user().await else {
                return Decision::Unauthenticated;
            };

            match auth_session.backend().get_all_permissions(&user).await {
                Ok(user_permissions) => {
                    let allow = match check_mode {
                        CheckMode::Any => required_permissions
                            .iter()
                            .any(|perm| user_permissions.contains(perm)),
                        CheckMode::All => required_permissions
                            .iter()
                            .all(|perm| user_permissions.contains(perm)),
                        CheckMode::Exact => user_permissions == *required_permissions,
                    };

                    if allow {
                        Decision::Allow
                    } else {
                        Decision::Unauthorized
                    }
                }
                Err(_) => Decision::Unauthorized,
            }
        })
    }
}

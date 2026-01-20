use std::{collections::HashSet, fmt::Debug, future::Future, marker::PhantomData, sync::Arc};

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
pub struct DefaultAccess<B: AuthnBackend, ST> {
    _marker: PhantomData<(B, ST)>,
}

impl<B: AuthnBackend, ST> Default for DefaultAccess<B, ST> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<B, ST> DecisionPredicate<B, ST> for DefaultAccess<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    fn decide(
        &self,
        auth_session: AuthSession<B>,
        _state: Arc<ST>,
    ) -> BoxFuture<'static, Decision> {
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

/// Defines how permissions should be matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMatch {
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
/// use axum_login::{
///     require::{PermissionMatch, PermissionsPredicate, Require},
///     AuthUser, AuthnBackend, AuthzBackend, UserId,
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
///     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
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
///     .with_mode(PermissionMatch::All);
///
/// let require = Require::<Backend>::builder().decision(predicate).build();
/// ```
pub struct PermissionsPredicate<B: AuthzBackend + AuthnBackend> {
    pub(crate) _marker: PhantomData<B>,
    // PERF: could add a single permission variant
    permissions: Arc<HashSet<B::Permission>>,
    match_mode: PermissionMatch,
}

impl<B: AuthnBackend + AuthzBackend> Default for PermissionsPredicate<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: AuthnBackend + AuthzBackend> PermissionsPredicate<B> {
    /// Create a new predicate with a single permission and ALL match mode.
    pub fn new() -> Self {
        let permissions: HashSet<B::Permission> = HashSet::new();
        Self {
            _marker: PhantomData,
            permissions: Arc::new(permissions),
            match_mode: PermissionMatch::All,
        }
    }
    /// Set the match mode for this predicate.
    pub fn with_mode(mut self, mode: PermissionMatch) -> Self {
        self.match_mode = mode;
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
    fn decide(
        &self,
        auth_session: AuthSession<B>,
        _state: Arc<ST>,
    ) -> BoxFuture<'static, Decision> {
        let required_permissions = Arc::clone(&self.permissions);
        let match_mode = self.match_mode;

        Box::pin(async move {
            let Some(user) = auth_session.user().await else {
                return Decision::Unauthenticated;
            };

            match auth_session.backend().get_all_permissions(&user).await {
                Ok(user_permissions) => {
                    let allow = match match_mode {
                        PermissionMatch::Any => required_permissions
                            .iter()
                            .any(|perm| user_permissions.contains(perm)),
                        PermissionMatch::All => required_permissions
                            .iter()
                            .all(|perm| user_permissions.contains(perm)),
                        PermissionMatch::Exact => user_permissions == *required_permissions,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tower_sessions::{MemoryStore, Session};

    use super::*;
    use crate::{AuthSession, AuthUser};

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestError;

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test error")
        }
    }

    impl std::error::Error for TestError {}

    impl AuthnBackend for TestBackend {
        type User = TestUser;
        type Credentials = ();
        type Error = TestError;

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

    impl AuthzBackend for TestBackend {
        type Permission = &'static str;

        async fn get_all_permissions(
            &self,
            _user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            Err(TestError)
        }
    }

    async fn auth_session_with_user() -> AuthSession<TestBackend> {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        let auth_session = AuthSession::from_session(session, TestBackend, "axum-login.data")
            .await
            .unwrap();
        auth_session.login(&TestUser).await.unwrap();
        auth_session
    }

    async fn auth_session_without_user() -> AuthSession<TestBackend> {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        AuthSession::from_session(session, TestBackend, "axum-login.data")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn default_access_returns_unauthenticated() {
        let predicate = DefaultAccess::<TestBackend, ()>::default();
        let auth_session = auth_session_without_user().await;

        let decision = predicate.decide(auth_session, Arc::new(())).await;

        assert_eq!(decision, Decision::Unauthenticated);
    }

    #[tokio::test]
    async fn default_access_returns_allow() {
        let predicate = DefaultAccess::<TestBackend, ()>::default();
        let auth_session = auth_session_with_user().await;

        let decision = predicate.decide(auth_session, Arc::new(())).await;

        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn permissions_predicate_denies_on_backend_error() {
        let predicate = PermissionsPredicate::<TestBackend>::new()
            .with_permissions(["admin.read"])
            .with_mode(PermissionMatch::Any);
        let auth_session = auth_session_with_user().await;

        let decision = predicate.decide(auth_session, Arc::new(())).await;

        assert_eq!(decision, Decision::Unauthorized);
    }
}

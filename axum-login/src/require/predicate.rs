use std::{
    collections::HashSet,
    fmt::Debug,
    future::{ready, Future, Ready},
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use pin_project::pin_project;

use crate::{AuthnBackend, AuthzBackend};
use crate::require::BoxFuture;
//PERF: this should be take references to backend, user and maybe state,
// otherwise we have to clone them every time. The problem is that references
// and async DO NOT combine well.

/// Trait for predicating requests
pub trait AsyncPredicate<B: AuthnBackend, ST = ()> {
    /// Async predicate Future should return bool
    type Future: Future<Output = bool>;
    /// Allow request, based on a given predicate
    ///
    /// The predicate takes the backend, the user and the state.
    ///
    /// See [`RequireBuilder::predicate`] for more details.
    ///
    /// [`RequireBuilder::predicate`]: super::builder::RequireBuilder
    fn predicate(&self, backend: B, user: <B as AuthnBackend>::User, state: ST) -> Self::Future;
}

/// The default [`AsyncPredicate`] implementation used by [`Require`].
#[derive(Clone, Debug)]
pub struct DefaultPredicate<B: AuthnBackend, ST> {
    pub(crate) _marker: PhantomData<(B, ST)>,
}

impl<B, ST> AsyncPredicate<B, ST> for DefaultPredicate<B, ST>
where
    B: AuthnBackend,
    ST: std::marker::Send + std::marker::Sync,
{
    type Future = Ready<bool>;

    fn predicate(&self, _backend: B, _user: <B as AuthnBackend>::User, _state: ST) -> Self::Future {
        ready(true)
    }
}
impl<F, Fut, B, ST> AsyncPredicate<B, ST> for F
where
    F: Fn(B, <B as AuthnBackend>::User, ST) -> Fut,
    Fut: Future<Output = bool>,
    B: AuthnBackend + AuthzBackend + 'static,
    B::User: 'static,
    B::Permission: Clone + Debug,
    ST: Clone + Send + Sync + 'static,
{
    type Future = Fut;

    fn predicate(&self, backend: B, user: <B as AuthnBackend>::User, state: ST) -> Self::Future {
        (self)(backend, user, state)
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
pub struct SimplePredicate<B: AuthzBackend + AuthnBackend> {
    pub(crate) _marker: PhantomData<B>,
    // PERF: maybe could add a single permission variant
    permissions: HashSet<B::Permission>,
    check_mode: CheckMode,
}

impl<B: AuthnBackend + AuthzBackend> Default for SimplePredicate<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: AuthnBackend + AuthzBackend> SimplePredicate<B> {
    /// Create a new SimplePredicate with a single permission and ALL check mode
    pub fn new() -> Self {
        let permissions: HashSet<B::Permission> = HashSet::new();
        Self {
            _marker: PhantomData,
            permissions,
            check_mode: CheckMode::All,
        }
    }
    /// Set the check mode for this predicate
    pub fn with_mode(mut self, mode: CheckMode) -> Self {
        self.check_mode = mode;
        self
    }

    /// Add permissions to the predicate
    pub fn with_permissions<I, P>(mut self, permissions: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<B::Permission>,
    {
        self.permissions = permissions.into_iter().map(Into::into).collect();
        self
    }
}

impl<B> AsyncPredicate<B, ()> for SimplePredicate<B>
where
    B: AuthnBackend + AuthzBackend + 'static,
    B::Permission: Clone,
{
    type Future = SimplePredicateFuture<B>;

    fn predicate(&self, backend: B, user: <B as AuthnBackend>::User, _state: ()) -> Self::Future {
        let backend = backend.clone();
        let user = user.clone();
        let required_permissions = self.permissions.clone();
        let check_mode = self.check_mode;

        SimplePredicateFuture::GetPermissions {
            future: Box::pin(async move { backend.get_all_permissions(&user).await }),
            required_permissions,
            check_mode,
        }
    }
}

#[pin_project(project = SimplePredicateFutureProj)]
#[allow(missing_debug_implementations)]
pub enum SimplePredicateFuture<B: AuthnBackend + AuthzBackend> {
    GetPermissions {
        #[pin]
        future: BoxFuture<'static, Result<HashSet<B::Permission>, B::Error>>,
        required_permissions: HashSet<B::Permission>,
        check_mode: CheckMode,
    },
    Ready {
        result: bool,
    },
}

impl<B> Future for SimplePredicateFuture<B>
where
    B: AuthnBackend + AuthzBackend,
    B::Permission: Clone + Eq + std::hash::Hash,
{
    type Output = bool;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.as_mut().project() {
                SimplePredicateFutureProj::GetPermissions {
                    future,
                    required_permissions,
                    check_mode,
                } => match future.poll(cx) {
                    Poll::Ready(Ok(user_permissions)) => {
                        let result = match check_mode {
                            CheckMode::Any => required_permissions
                                .iter()
                                .any(|perm| user_permissions.contains(perm)),
                            CheckMode::All => required_permissions
                                .iter()
                                .all(|perm| user_permissions.contains(perm)),
                            CheckMode::Exact => user_permissions == *required_permissions,
                        };
                        self.set(SimplePredicateFuture::Ready { result });
                    }
                    Poll::Ready(Err(_)) => {
                        self.set(SimplePredicateFuture::Ready { result: false });
                    }
                    Poll::Pending => return Poll::Pending,
                },
                SimplePredicateFutureProj::Ready { result } => {
                    return Poll::Ready(*result);
                }
            }
        }
    }
}

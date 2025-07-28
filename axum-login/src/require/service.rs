use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;
use crate::{AuthSession, AuthnBackend};
use crate::require::{BoxFuture, FallbackFn, PredicateStateFn, RestrictFn};
use axum::body::Body;
use axum::response::Response;
use axum::extract::{OriginalUri, Request};
use axum::http::StatusCode;

/// A Tower service that enforces authentication and authorization requirements.
///
/// This service checks for authentication, if it fails, it responds with fallback applies a
/// predicate function to determine if
/// the request should
/// be
/// allowed to proceed. If the predicate fails, it applies either a restriction response or a fallback response.
pub struct RequireService<S, B: AuthnBackend, ST: Clone, T> {
    pub(crate) inner: S,
    /// Function used to check user permissions or other requirements
    pub(crate) predicate: PredicateStateFn<B, ST>,
    /// Handler used in case the user fails authentication
    pub(crate) fallback: FallbackFn<T>,
    /// State of the application
    pub(crate) state: ST,
    /// Handler used in case the user fails predicate check
    pub(crate) restrict: RestrictFn<T>,
}

impl<S, B, ST, T> fmt::Debug for RequireService<S, B, ST, T>
where
    S: fmt::Debug,
    B: AuthnBackend,
    ST: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireService")
            .field("inner", &self.inner)
            .field("predicate", &"<function>")
            .field("fallback", &"<function>")
            .field("state", &self.state)
            .field("restrict", &"<function>")
            .finish()
    }
}

//umm, manual clone, yes
impl<S, B, ST, T> Clone for RequireService<S, B, ST, T>
where
    S: Clone,
    ST: Clone,
    B: AuthnBackend,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            predicate: self.predicate.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            restrict: self.restrict.clone(),
        }
    }
}

impl<S, B, ST, T> Service<Request<T>> for RequireService<S, B, ST, T>
where
    S: Service<Request<T>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: AuthnBackend + Clone + Send + 'static,
    ST: Clone + Send + 'static,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();

        let predicate = Arc::clone(&self.predicate);
        let fallback = Arc::clone(&self.fallback);
        let restrict = Arc::clone(&self.restrict);
        let state = self.state.clone();

        // This should help
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            match auth_session {
                Some(AuthSession {
                         user: Some(user),
                         backend,
                         ..
                     }) => {
                    // Only enter here if user is Some(...)
                    if predicate(backend, user.clone(), state).await {
                        // Authorized
                        let response = inner.call(req).await?;
                        Ok(response)
                    } else {
                        // Restricted
                        let response = restrict(req).await;
                        Ok(response)
                    }
                }
                Some(_auth_session) => {
                    // No user in session, use fallback
                    let response = fallback(req).await;
                    Ok(response)
                }
                _ => {
                    // Missing required extensions
                    Ok(axum::response::IntoResponse::into_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        })
    }
}

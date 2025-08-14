use crate::backend;
use crate::require::{BoxFuture, Require, RestrictFn};
use crate::{AuthSession, AuthnBackend};
use axum::body::Body;
use axum::http;
use axum::response::IntoResponse;
use http::{Request, Response, StatusCode};
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// A Tower service that enforces authentication and authorization requirepub(crate) ments.
///
/// This service checks for authentication, if it fails, it responds with fallback applies a
/// pub(crate) pub(crate) predicate function to determine if
/// the request should
/// be
/// allowed to proceed. If the predicate fails, it applies either a restpub(crate)riction response or a fallback response.
#[must_use]
pub struct RequireService<S, B: AuthnBackend + Clone, ST: Clone, T = ()> {
    pub(crate) inner: S,
    pub(crate) layer: Require<B, ST, T>,
}
impl<S: Clone, B: backend::AuthnBackend, ST: std::clone::Clone, T> Clone
for RequireService<S, B, ST, T>
{
    fn clone(&self) -> Self {
        RequireService {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, ST, T> Service<Request<T>> for RequireService<S, B, ST, T>
where
    S: Service<Request<T>, Response=Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: AuthnBackend + Clone + Send + 'static,
    ST: Clone + Send + 'static,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RequireFuture<S, T>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();
        //PERF: I am not exactly sure, but there is a potential optimization to include `restrict()`
        //as a part of `predicate()`
        let restrict = Arc::clone(&self.layer.restrict);
        let state = self.layer.state.clone();

        // Clone inner service for the future
        let mut inner = self.inner.clone();
        // mem::swap due to https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        std::mem::swap(&mut self.inner, &mut inner);

        match auth_session {
            Some(AuthSession {
                     user: Some(user),
                     backend,
                     ..
                 }) => {
                // User is authenticated, check predicate
                let predicate_future = (self.layer.predicate)(backend, user.clone(), state);
                RequireFuture {
                    state: RequireFutureState::CheckingPredicate {
                        predicate_future,
                        inner,
                        request: Some(req),
                        restrict,
                    },
                }
            }
            Some(_auth_session) => {
                // No user in session, use fallback
                let fallback_future = (self.layer.fallback)(req);
                RequireFuture {
                    state: RequireFutureState::CallingFallback { fallback_future },
                }
            }
            None => {
                // Missing required extensions - return internal server error
                let error_response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
                let fallback_future = Box::pin(async move { error_response });
                RequireFuture {
                    state: RequireFutureState::CallingFallback { fallback_future },
                }
            }
        }
    }
}

#[pin_project]
pub struct RequireFuture<S, T>
where
    S: Service<Request<T>, Response=Response<Body>>,
{
    #[pin]
    state: RequireFutureState<S, T>,
}

#[pin_project(project = RequireFutureStateProj)]
pub enum RequireFutureState<S, T>
where
    S: Service<Request<T>, Response=Response<Body>>,
{
    CheckingPredicate {
        #[pin]
        predicate_future: BoxFuture<'static, bool>,
        inner: S,
        request: Option<Request<T>>,
        restrict: RestrictFn<T>,
    },
    CallingInner {
        #[pin]
        inner_future: S::Future,
    },
    CallingRestrict {
        #[pin]
        restrict_future: BoxFuture<'static, Response<Body>>,
    },
    CallingFallback {
        #[pin]
        fallback_future: BoxFuture<'static, Response<Body>>,
    },
    Error,
}

impl<S, T> Future for RequireFuture<S, T>
where
    S: Service<Request<T>, Response=Response<Body>> + Send + 'static,
{
    type Output = Result<Response<Body>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RequireFutureStateProj::CheckingPredicate {
                    predicate_future,
                    inner,
                    request,
                    restrict,
                } => {
                    match predicate_future.poll(cx) {
                        Poll::Ready(true) => {
                            // Predicate passed, call inner service
                            let req = request.take().expect("Request should be available");
                            let inner_future = inner.call(req);
                            this.state
                                .set(RequireFutureState::CallingInner { inner_future });
                        }
                        Poll::Ready(false) => {
                            // Predicate failed, call restrict handler
                            let req = request.take().expect("Request should be available");
                            let restrict_future = restrict(req);
                            this.state
                                .set(RequireFutureState::CallingRestrict { restrict_future });
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RequireFutureStateProj::CallingInner { inner_future } => {
                    return match inner_future.poll(cx) {
                        Poll::Ready(result) => Poll::Ready(result),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::CallingRestrict { restrict_future } => {
                    return match restrict_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::CallingFallback { fallback_future } => {
                    return match fallback_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::Error => {
                    panic!("Future polled after completion")
                }
            }
        }
    }
}

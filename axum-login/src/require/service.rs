use crate::require::handler::{AsyncFallbackHandler, InternalErrorFallback};
use crate::require::{BoxFuture, Require};
use crate::{AuthSession, AuthnBackend};
use axum::body::Body;
use axum::http;
use http::{Request, Response};
use pin_project::pin_project;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower_service::Service;

/// A Tower service that enforces authentication and authorization requirepub(crate) ments.
///
/// This service checks for authentication, if it fails, it responds with fallback applies a
/// pub(crate) pub(crate) predicate function to determine if
/// the request should
/// be
/// allowed to proceed. If the predicate fails, it applies either a restpub(crate)riction response or a fallback response.
#[must_use]
pub struct RequireService<
    S,
    B: AuthnBackend + Clone,
    ST: Clone,
    T: std::marker::Send + 'static,
    Fb: Clone + std::marker::Send + std::marker::Sync + 'static,
    Rs: Clone + std::marker::Send + std::marker::Sync + 'static,
> {
    pub(crate) inner: S,
    pub(crate) layer: Require<B, ST, T, Fb, Rs>,
}
impl<
        S: Clone,
        B: AuthnBackend,
        Fb: Clone + std::marker::Sync + std::marker::Send,
        Rs: Clone + std::marker::Send + std::marker::Sync + 'static,
        ST: Clone,
        T: Send,
    > Clone for RequireService<S, B, ST, T, Fb, Rs>
{
    fn clone(&self) -> Self {
        RequireService {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, Fb, Rs, ST, T> Service<Request<T>> for RequireService<S, B, ST, T, Fb, Rs>
where
    S: Service<Request<T>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: AuthnBackend + Clone + Send + 'static,
    ST: Clone + Send + 'static,
    Fb: AsyncFallbackHandler<T, Response = S::Response> + Clone + std::marker::Sync + std::marker::Send,
    Rs: AsyncFallbackHandler<T, Response = S::Response> + Clone + std::marker::Sync + std::marker::Send,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RequireFuture<S, T, Fb, Rs>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();
        //PERF: Not exactly sure, but there is a potential optimization to include `restrict()`
        //as a part of `predicate()`
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
                        restrict: self.layer.restrict.clone(), //PERF: avoid cloning
                    },
                }
            }
            Some(_auth_session) => {
                // No user in session, use fallback
                let fallback_future = self.layer.fallback.handle(req);
                RequireFuture {
                    state: RequireFutureState::CallingFallback {
                        fallback_future,
                        phantom_data: PhantomData,
                    },
                }
            }
            None => {
                // Missing required extensions - return internal server error
                let internal_fallback_future = InternalErrorFallback.handle(req);

                RequireFuture {
                    state: RequireFutureState::CallingInternalFallback {
                        internal_fallback_future,
                    },
                }
            }
        }
    }
}

#[pin_project]
pub struct RequireFuture<S, T, Fb, Rs>
where
    S: Service<Request<T>, Response = Response<Body>>,
    Fb: AsyncFallbackHandler<T> + Clone,
    Rs: AsyncFallbackHandler<T> + Clone,
{
    #[pin]
    state: RequireFutureState<S, T, Fb, Rs>,
}

#[pin_project(project = RequireFutureStateProj)]
pub enum RequireFutureState<S, T, Fb, Rs>
where
    S: Service<Request<T>, Response = Response<Body>>,
    Fb: AsyncFallbackHandler<T> + Clone,
    Rs: AsyncFallbackHandler<T> + Clone,
{
    CheckingPredicate {
        #[pin]
        predicate_future: BoxFuture<'static, bool>,
        inner: S,
        request: Option<Request<T>>,
        restrict: Rs,
    },
    CallingInner {
        #[pin]
        inner_future: S::Future,
    },
    CallingRestrict {
        #[pin]
        restrict_future: Rs::Future,
        phantom_data: PhantomData<Rs>,
    },
    CallingFallback {
        #[pin]
        fallback_future: Fb::Future,
        phantom_data: PhantomData<Fb>,
    },
    CallingInternalFallback {
        #[pin]
        internal_fallback_future: <InternalErrorFallback as AsyncFallbackHandler<Body>>::Future,
    },
}

impl<S, T, Fb, Rs> Future for RequireFuture<S, T, Fb, Rs>
where
    S: Service<Request<T>, Response = Response<Body>> + Send + 'static,
    Fb: AsyncFallbackHandler<T, Response = Response<Body>> + Clone,
    Rs: AsyncFallbackHandler<T, Response = Response<Body>> + Clone,
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
                            let restrict_future = restrict.handle(req);
                            this.state
                                .set(RequireFutureState::CallingRestrict { restrict_future, phantom_data: PhantomData });
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
                RequireFutureStateProj::CallingRestrict { restrict_future ,..} => {
                    return match restrict_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::CallingFallback {
                    fallback_future, ..
                } => {
                    return match fallback_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::CallingInternalFallback {
                    internal_fallback_future,
                } => {
                    return match internal_fallback_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
            }
        }
    }
}

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{body::Body, http};
use http::{Request, Response};
use pin_project::pin_project;
use tower_service::Service;

use crate::{
    require::{
        handler::{AsyncFallbackHandler, InternalErrorFallback},
        predicate::AsyncPredicate,
        Require,
    },
    AuthSession, AuthnBackend,
};

/// A Tower service that enforces authentication and authorization
/// requirements.
///
/// This service checks for authentication, if it fails, it responds with
/// fallback applies a pub(crate) pub(crate) predicate function to determine if
/// the request should
/// be
/// allowed to proceed. If the predicate fails, it applies either a
/// restriction response or a fallback response.
#[must_use]
#[derive(Debug)]
pub struct RequireService<
    S,
    B: AuthnBackend + Clone + 'static,
    ST: Clone + std::marker::Send + 'static,
    T: std::marker::Send + 'static,
    Fb: Clone + std::marker::Send + std::marker::Sync + 'static,
    Rs: Clone + std::marker::Send + std::marker::Sync + 'static,
    Pr: Clone + std::marker::Send + std::marker::Sync + 'static,
> {
    pub(crate) inner: S,
    pub(crate) layer: Require<B, ST, T, Fb, Rs, Pr>,
}
impl<
        S: Clone,
        B: AuthnBackend,
        Fb: Clone + std::marker::Sync + std::marker::Send,
        Rs: Clone + std::marker::Send + std::marker::Sync + 'static,
        Pr: Clone + std::marker::Send + std::marker::Sync + 'static,
        ST: Clone + std::marker::Send,
        T: Send,
    > Clone for RequireService<S, B, ST, T, Fb, Rs, Pr>
{
    fn clone(&self) -> Self {
        RequireService {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, Fb, Rs, ST, T, Pr> Service<Request<T>> for RequireService<S, B, ST, T, Fb, Rs, Pr>
where
    S: Service<Request<T>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: AuthnBackend + Clone + Send + 'static,
    ST: Clone + Send + 'static,
    Fb: AsyncFallbackHandler<T, Response = S::Response>
        + Clone
        + std::marker::Sync
        + std::marker::Send,
    Rs: AsyncFallbackHandler<T, Response = S::Response>
        + Clone
        + std::marker::Sync
        + std::marker::Send,
    Pr: AsyncPredicate<B, ST> + std::clone::Clone + Send + Sync,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RequireFuture<S, T, Fb, Rs, Pr, B, ST>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        //PERF: clone needed?
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();
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
                // PERF: clone...
                let predicate_future =
                    (self.layer)
                        .predicate
                        .predicate(backend, user.clone(), state);
                RequireFuture {
                    state: RequireFutureState::Predicate {
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
                    state: RequireFutureState::Fallback {
                        fallback_future,
                        phantom_data: PhantomData,
                    },
                }
            }
            None => {
                // Missing required extensions - return internal server error
                let internal_fallback_future = InternalErrorFallback.handle(req);

                RequireFuture {
                    state: RequireFutureState::InternalFallback {
                        internal_fallback_future,
                    },
                }
            }
        }
    }
}

#[pin_project]
/// Response future for [`Require`].
#[allow(missing_debug_implementations)]
pub struct RequireFuture<S, T, Fb, Rs, Pr, B, ST>
where
    S: Service<Request<T>, Response = Response<Body>>,
    Fb: AsyncFallbackHandler<T> + Clone,
    Rs: AsyncFallbackHandler<T> + Clone,
    Pr: AsyncPredicate<B, ST>,
    B: AuthnBackend,
{
    #[pin]
    state: RequireFutureState<S, T, Fb, Rs, Pr, B, ST>,
}

#[pin_project(project = RequireFutureStateProj)]
#[allow(missing_debug_implementations)]
pub(super) enum RequireFutureState<S, T, Fb, Rs, Pr, B, ST>
where
    Pr: AsyncPredicate<B, ST>,
    S: Service<Request<T>, Response = Response<Body>>,
    Fb: AsyncFallbackHandler<T> + Clone,
    Rs: AsyncFallbackHandler<T> + Clone,
    B: AuthnBackend,
{
    Predicate {
        #[pin]
        predicate_future: Pr::Future,
        inner: S,
        request: Option<Request<T>>,
        restrict: Rs,
    },
    Inner {
        #[pin]
        inner_future: S::Future,
    },
    Restrict {
        #[pin]
        restrict_future: Rs::Future,
        phantom_data: PhantomData<Rs>,
    },
    Fallback {
        #[pin]
        fallback_future: Fb::Future,
        phantom_data: PhantomData<Fb>,
    },
    InternalFallback {
        #[pin]
        internal_fallback_future: <InternalErrorFallback as AsyncFallbackHandler<Body>>::Future,
    },
}

impl<S, T, Fb, Rs, Pr, B, ST> Future for RequireFuture<S, T, Fb, Rs, Pr, B, ST>
where
    S: Service<Request<T>, Response = Response<Body>> + Send + 'static,
    Fb: AsyncFallbackHandler<T, Response = Response<Body>> + Clone,
    Rs: AsyncFallbackHandler<T, Response = Response<Body>> + Clone,
    Pr: AsyncPredicate<B, ST> + Send + 'static,
    B: AuthnBackend,
{
    type Output = Result<Response<Body>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RequireFutureStateProj::Predicate {
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
                                .set(RequireFutureState::Inner { inner_future });
                        }
                        Poll::Ready(false) => {
                            // Predicate failed, call restrict handler
                            let req = request.take().expect("Request should be available");
                            let restrict_future = restrict.handle(req);
                            this.state.set(RequireFutureState::Restrict {
                                restrict_future,
                                phantom_data: PhantomData,
                            });
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RequireFutureStateProj::Inner { inner_future } => {
                    return match inner_future.poll(cx) {
                        Poll::Ready(result) => Poll::Ready(result),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::Restrict {
                    restrict_future, ..
                } => {
                    return match restrict_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::Fallback {
                    fallback_future, ..
                } => {
                    return match fallback_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::InternalFallback {
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

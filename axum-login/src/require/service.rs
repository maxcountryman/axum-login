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
        BoxFuture, Require,
    },
    AuthSession, AuthnBackend,
};

fn internal_error_response() -> Response<Body> {
    http::Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("Internal Server Error"))
        .unwrap_or_else(|_| http::Response::new(Body::empty()))
}

/// A Tower service that enforces authentication and authorization.
///
/// The service checks whether a request is authenticated. If it is, it
/// evaluates the predicate and either forwards to the inner service or applies
/// the restrict handler. If it is not, it applies the fallback handler.
#[must_use]
#[derive(Debug)]
pub struct RequireService<S, B: AuthnBackend, ST, T, Fb, Rs, Pr> {
    pub(crate) inner: S,
    pub(crate) layer: Require<B, ST, T, Fb, Rs, Pr>,
}

// Manual clone because Body isn't Clone on the service type.
impl<S, B, Fb, Rs, Pr, ST, T> Clone for RequireService<S, B, ST, T, Fb, Rs, Pr>
where
    S: Clone,
    B: AuthnBackend,
    Fb: Clone,
    Rs: Clone,
    Pr: Clone,
    ST: Clone,
{
    fn clone(&self) -> Self {
        RequireService {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, Fb, Rs, ST, T: 'static, Pr> Service<Request<T>>
    for RequireService<S, B, ST, T, Fb, Rs, Pr>
where
    S: Service<Request<T>, Response = Response<Body>> + Clone,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Clone + 'static,
    Fb: AsyncFallbackHandler<T, Response = S::Response>,
    Rs: AsyncFallbackHandler<T, Response = S::Response>,
    Pr: AsyncPredicate<B, ST> + Clone + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = RequireFuture<S, T, Fb, Rs, Pr, B, ST>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();

        // Clone inner service for the future.
        let mut inner = self.inner.clone();
        // Avoid cloning the inner service twice as recommended by tower.
        std::mem::swap(&mut self.inner, &mut inner);
        match auth_session {
            Some(auth_session) => {
                // Check if user exists (async operation).
                let backend = auth_session.backend().clone();
                let user_future = Box::pin(async move { auth_session.user().await });
                RequireFuture {
                    state: RequireFutureState::CheckingUser {
                        request: Some(req),
                        backend,
                        user_future,
                    },
                    fallback: self.layer.fallback.clone(),
                    restrict: self.layer.restrict.clone(),
                    predicate: self.layer.predicate.clone(),
                    app_state: self.layer.state.clone(),
                    service: inner,
                }
            }
            None => {
                // Missing required extensions: return internal server error.
                let internal_fallback_future = InternalErrorFallback.handle(req);

                RequireFuture {
                    state: RequireFutureState::InternalFallback {
                        internal_fallback_future,
                    },
                    fallback: self.layer.fallback.clone(),
                    restrict: self.layer.restrict.clone(),
                    predicate: self.layer.predicate.clone(),
                    app_state: self.layer.state.clone(),
                    service: inner,
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
    Rs: AsyncFallbackHandler<T>,
    Pr: AsyncPredicate<B, ST>,
    B: AuthnBackend,
{
    #[pin]
    state: RequireFutureState<S::Future, T, Fb, Rs, B>,
    service: S,
    fallback: Fb,
    restrict: Rs,
    predicate: Pr,
    app_state: ST,
}

#[pin_project(project = RequireFutureStateProj)]
#[allow(missing_debug_implementations)]
pub(super) enum RequireFutureState<SFut, T, Fb, Rs, B>
where
    Fb: AsyncFallbackHandler<T>,
    Rs: AsyncFallbackHandler<T>,
    B: AuthnBackend,
{
    CheckingUser {
        request: Option<Request<T>>,
        #[pin]
        user_future: BoxFuture<'static, Option<B::User>>,
        backend: B,
    },
    Predicate {
        request: Option<Request<T>>,
        #[pin]
        predicate_future: BoxFuture<'static, bool>,
    },
    Inner {
        #[pin]
        inner_future: SFut,
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
        internal_fallback_future: <InternalErrorFallback as AsyncFallbackHandler<T>>::Future,
    },
}

impl<S, T, Fb, Rs, Pr, B, ST> Future for RequireFuture<S, T, Fb, Rs, Pr, B, ST>
where
    S: Service<Request<T>, Response = Response<Body>> + Clone,
    Fb: AsyncFallbackHandler<T, Response = Response<Body>>,
    Rs: AsyncFallbackHandler<T, Response = Response<Body>>,
    Pr: AsyncPredicate<B, ST> + Clone + 'static,
    B: AuthnBackend + 'static,
    ST: Clone + 'static,
{
    type Output = Result<Response<Body>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RequireFutureStateProj::CheckingUser {
                    request,
                    user_future,
                    backend,
                } => {
                    match user_future.poll(cx) {
                        Poll::Ready(Some(user)) => {
                            // User is authenticated, check predicate
                            let backend_clone = backend.clone();
                            let predicate_future = Box::pin(this.predicate.predicate(
                                backend_clone,
                                user,
                                this.app_state.clone(),
                            ));

                            let request = request.take();
                            this.state.set(RequireFutureState::Predicate {
                                request,
                                predicate_future,
                            });
                        }
                        Poll::Ready(None) => {
                            // No user in session, use fallback
                            let Some(request) = request.take() else {
                                return Poll::Ready(Ok(internal_error_response()));
                            };
                            let fallback_future = this.fallback.handle(request);
                            this.state.set(RequireFutureState::Fallback {
                                fallback_future,
                                phantom_data: PhantomData,
                            });
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RequireFutureStateProj::Predicate {
                    request,
                    predicate_future,
                } => {
                    match predicate_future.poll(cx) {
                        Poll::Ready(true) => {
                            // Predicate passed, call inner service
                            let Some(request) = request.take() else {
                                return Poll::Ready(Ok(internal_error_response()));
                            };
                            let inner_future = this.service.call(request);
                            this.state.set(RequireFutureState::Inner { inner_future });
                        }
                        Poll::Ready(false) => {
                            // Predicate failed, call restrict handler
                            let Some(request) = request.take() else {
                                return Poll::Ready(Ok(internal_error_response()));
                            };
                            let restrict_future = this.restrict.handle(request);
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

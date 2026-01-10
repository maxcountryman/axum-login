use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{body::Body, http};
use http::{Request, Response};
use pin_project::pin_project;
use tower_service::Service;

use crate::{
    require::{
        handler::{InternalErrorFallback, ResponseHandler},
        predicate::Decision,
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
/// the unauthorized handler. If it is not, it applies the unauthenticated
/// handler.
#[must_use]
#[derive(Debug)]
pub struct RequireService<S, B: AuthnBackend + Send + Sync + 'static, ST, T> {
    pub(crate) inner: S,
    pub(crate) layer: Require<B, ST, T>,
}

// Manual clone because Body isn't Clone on the service type.
impl<S, B, ST, T> Clone for RequireService<S, B, ST, T>
where
    S: Clone,
    B: AuthnBackend + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        RequireService {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S, B, ST, T: 'static> Service<Request<T>> for RequireService<S, B, ST, T>
where
    S: Service<Request<T>, Response = Response<Body>> + Clone,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
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

        // Clone inner service for the future.
        let mut inner = self.inner.clone();
        // Avoid cloning the inner service twice as recommended by tower.
        std::mem::swap(&mut self.inner, &mut inner);

        match auth_session {
            Some(auth_session) => {
                let decision_future = self
                    .layer
                    .decision
                    .decide(auth_session, Arc::clone(&self.layer.state));

                RequireFuture {
                    state: RequireFutureState::CheckingUser {
                        request: Box::new(Some(req)),
                        decision_future,
                    },
                    unauthenticated: Arc::clone(&self.layer.unauthenticated),
                    unauthorized: Arc::clone(&self.layer.unauthorized),
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
                    unauthenticated: Arc::clone(&self.layer.unauthenticated),
                    unauthorized: Arc::clone(&self.layer.unauthorized),
                    service: inner,
                }
            }
        }
    }
}

#[pin_project]
/// Response future for [`Require`].
#[allow(missing_debug_implementations)]
pub struct RequireFuture<S, T>
where
    S: Service<Request<T>, Response = Response<Body>>,
{
    #[pin]
    state: RequireFutureState<S::Future, T>,
    service: S,
    unauthenticated: Arc<dyn ResponseHandler<T>>,
    unauthorized: Arc<dyn ResponseHandler<T>>,
}

#[pin_project(project = RequireFutureStateProj)]
#[allow(missing_debug_implementations)]
pub(super) enum RequireFutureState<SFut, T> {
    CheckingUser {
        request: Box<Option<Request<T>>>,
        #[pin]
        decision_future: BoxFuture<'static, Decision>,
    },
    Inner {
        #[pin]
        inner_future: SFut,
    },
    Unauthorized {
        #[pin]
        unauthorized_future: BoxFuture<'static, Response<Body>>,
    },
    Unauthenticated {
        #[pin]
        unauthenticated_future: BoxFuture<'static, Response<Body>>,
    },
    InternalFallback {
        #[pin]
        internal_fallback_future: BoxFuture<'static, Response<Body>>,
    },
}

impl<S, T> Future for RequireFuture<S, T>
where
    S: Service<Request<T>, Response = Response<Body>> + Clone,
{
    type Output = Result<Response<Body>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                RequireFutureStateProj::CheckingUser {
                    request,
                    decision_future,
                } => match decision_future.poll(cx) {
                    Poll::Ready(Decision::Allow) => {
                        let Some(request) = request.as_mut().take() else {
                            return Poll::Ready(Ok(internal_error_response()));
                        };
                        let inner_future = this.service.call(request);
                        this.state.set(RequireFutureState::Inner { inner_future });
                    }
                    Poll::Ready(Decision::Unauthorized) => {
                        let Some(request) = request.as_mut().take() else {
                            return Poll::Ready(Ok(internal_error_response()));
                        };
                        let unauthorized_future = this.unauthorized.handle(request);
                        this.state.set(RequireFutureState::Unauthorized {
                            unauthorized_future,
                        });
                    }
                    Poll::Ready(Decision::Unauthenticated) => {
                        let Some(request) = request.as_mut().take() else {
                            return Poll::Ready(Ok(internal_error_response()));
                        };
                        let unauthenticated_future = this.unauthenticated.handle(request);
                        this.state.set(RequireFutureState::Unauthenticated {
                            unauthenticated_future,
                        });
                    }
                    Poll::Pending => return Poll::Pending,
                },
                RequireFutureStateProj::Inner { inner_future } => {
                    return match inner_future.poll(cx) {
                        Poll::Ready(result) => Poll::Ready(result),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::Unauthorized {
                    unauthorized_future,
                } => {
                    return match unauthorized_future.poll(cx) {
                        Poll::Ready(response) => Poll::Ready(Ok(response)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                RequireFutureStateProj::Unauthenticated {
                    unauthenticated_future,
                } => {
                    return match unauthenticated_future.poll(cx) {
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

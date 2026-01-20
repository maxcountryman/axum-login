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
        BoxFuture, Require, RequireState,
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
    type Future = RequireFuture<S, B, ST, T>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Always ready: only poll the inner service once the decision allows.
        let _ = cx;
        Poll::Ready(Ok(()))
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
                    .inner
                    .decision
                    .decide(auth_session, Arc::clone(&self.layer.inner.state));

                RequireFuture {
                    state: RequireFutureState::CheckingUser {
                        request: Box::new(Some(req)),
                        decision_future,
                    },
                    inner: Arc::clone(&self.layer.inner),
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
                    inner: Arc::clone(&self.layer.inner),
                    service: inner,
                }
            }
        }
    }
}

#[pin_project]
/// Response future for [`Require`].
#[allow(missing_debug_implementations)]
pub struct RequireFuture<S, B, ST, T>
where
    S: Service<Request<T>, Response = Response<Body>>,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    #[pin]
    state: RequireFutureState<S::Future, T>,
    service: S,
    inner: Arc<RequireState<B, ST, T>>,
}

#[pin_project(project = RequireFutureStateProj)]
#[allow(missing_debug_implementations)]
pub(super) enum RequireFutureState<SFut, T> {
    CheckingUser {
        request: Box<Option<Request<T>>>,
        #[pin]
        decision_future: BoxFuture<'static, Decision>,
    },
    WaitingReady {
        request: Box<Option<Request<T>>>,
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

impl<S, B, ST, T> Future for RequireFuture<S, B, ST, T>
where
    S: Service<Request<T>, Response = Response<Body>> + Clone,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
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
                        this.state.set(RequireFutureState::WaitingReady {
                            request: Box::new(Some(request)),
                        });
                    }
                    Poll::Ready(Decision::Unauthorized) => {
                        let Some(request) = request.as_mut().take() else {
                            return Poll::Ready(Ok(internal_error_response()));
                        };
                        let unauthorized_future = this.inner.unauthorized.handle(request);
                        this.state.set(RequireFutureState::Unauthorized {
                            unauthorized_future,
                        });
                    }
                    Poll::Ready(Decision::Unauthenticated) => {
                        let Some(request) = request.as_mut().take() else {
                            return Poll::Ready(Ok(internal_error_response()));
                        };
                        let unauthenticated_future = this.inner.unauthenticated.handle(request);
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
                RequireFutureStateProj::WaitingReady { request } => {
                    match this.service.poll_ready(cx) {
                        Poll::Ready(Ok(())) => {
                            let Some(request) = request.as_mut().take() else {
                                return Poll::Ready(Ok(internal_error_response()));
                            };
                            let inner_future = this.service.call(request);
                            this.state.set(RequireFutureState::Inner { inner_future });
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        task::{Wake, Waker},
    };

    use axum::body::Body;
    use http::{Request, Response, StatusCode};
    use tower_service::Service;
    use tower_sessions::{MemoryStore, Session};

    use super::*;
    use crate::{
        require::{Decision, DefaultAccess, Require, SimpleResponseHandler},
        AuthSession, AuthUser, AuthnBackend,
    };

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

    impl AuthnBackend for TestBackend {
        type User = TestUser;
        type Credentials = ();
        type Error = std::convert::Infallible;

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

    #[derive(Clone)]
    struct GateService {
        ready: Arc<AtomicBool>,
        poll_ready_calls: Arc<AtomicUsize>,
        call_count: Arc<AtomicUsize>,
    }

    impl GateService {
        fn new() -> Self {
            Self {
                ready: Arc::new(AtomicBool::new(false)),
                poll_ready_calls: Arc::new(AtomicUsize::new(0)),
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Service<Request<Body>> for GateService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<'static, Result<Response<Body>, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_ready_calls.fetch_add(1, Ordering::SeqCst);
            if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("ok"))
                    .unwrap())
            })
        }
    }

    async fn auth_session() -> AuthSession<TestBackend> {
        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        AuthSession::from_session(session, TestBackend, "axum-login.data")
            .await
            .unwrap()
    }

    fn require_allow() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Allow },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    fn require_unauthorized() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Unauthorized },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    fn require_unauthenticated() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Unauthenticated },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ReadyError;

    #[derive(Clone)]
    struct ErrorReadyService;

    impl Service<Request<Body>> for ErrorReadyService {
        type Response = Response<Body>;
        type Error = ReadyError;
        type Future = BoxFuture<'static, Result<Response<Body>, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(ReadyError))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            Box::pin(async move {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("ok"))
                    .unwrap())
            })
        }
    }

    fn noop_waker() -> Waker {
        struct NoopWake;

        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        Waker::from(Arc::new(NoopWake))
    }

    #[tokio::test]
    async fn poll_ready_does_not_poll_inner() {
        let gate = GateService::new();
        let require = require_allow();
        let mut service = RequireService {
            inner: gate.clone(),
            layer: require,
        };

        let waker = noop_waker();
        let _ = service.poll_ready(&mut Context::from_waker(&waker));
        assert_eq!(gate.poll_ready_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn allow_waits_for_inner_readiness() {
        let gate = GateService::new();
        let require = require_allow();
        let mut service = RequireService {
            inner: gate.clone(),
            layer: require,
        };

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(auth_session().await);

        let mut fut = service.call(req);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending));
        assert_eq!(gate.poll_ready_calls.load(Ordering::SeqCst), 1);

        gate.ready.store(true, Ordering::SeqCst);
        let res = Pin::new(&mut fut).poll(&mut cx);
        let res = match res {
            Poll::Ready(Ok(res)) => res,
            _ => panic!("expected ready response"),
        };
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(gate.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unauthorized_does_not_poll_inner() {
        let gate = GateService::new();
        let require = require_unauthorized();
        let mut service = RequireService {
            inner: gate.clone(),
            layer: require,
        };

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(auth_session().await);

        let res = service.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(gate.poll_ready_calls.load(Ordering::SeqCst), 0);
        assert_eq!(gate.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unauthenticated_does_not_poll_inner() {
        let gate = GateService::new();
        let require = require_unauthenticated();
        let mut service = RequireService {
            inner: gate.clone(),
            layer: require,
        };

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(auth_session().await);

        let res = service.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(gate.poll_ready_calls.load(Ordering::SeqCst), 0);
        assert_eq!(gate.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_auth_session_returns_internal_error() {
        let gate = GateService::new();
        let require = require_allow();
        let mut service = RequireService {
            inner: gate.clone(),
            layer: require,
        };

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = service.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(gate.poll_ready_calls.load(Ordering::SeqCst), 0);
        assert_eq!(gate.call_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn allow_propagates_inner_ready_error() {
        let require = require_allow();
        let mut service = RequireService {
            inner: ErrorReadyService,
            layer: require,
        };

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(auth_session().await);

        let err = service.call(req).await.unwrap_err();
        assert_eq!(err, ReadyError);
    }

    #[test]
    fn checking_user_missing_request_returns_internal_error() {
        let mut fut = RequireFuture {
            state: RequireFutureState::CheckingUser {
                request: Box::new(None),
                decision_future: Box::pin(async { Decision::Allow }),
            },
            inner: Arc::new(RequireState {
                decision: Arc::new(DefaultAccess::<TestBackend, ()>::default()),
                unauthorized: Arc::new(SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope")),
                unauthenticated: Arc::new(SimpleResponseHandler::text(
                    StatusCode::UNAUTHORIZED,
                    "nope",
                )),
                state: Arc::new(()),
            }),
            service: GateService::new(),
        };

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let res = match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(Ok(res)) => res,
            other => panic!("expected ready response, got {other:?}"),
        };

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn unauthorized_missing_request_returns_internal_error() {
        let mut fut = RequireFuture {
            state: RequireFutureState::CheckingUser {
                request: Box::new(None),
                decision_future: Box::pin(async { Decision::Unauthorized }),
            },
            inner: Arc::new(RequireState {
                decision: Arc::new(DefaultAccess::<TestBackend, ()>::default()),
                unauthorized: Arc::new(SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope")),
                unauthenticated: Arc::new(SimpleResponseHandler::text(
                    StatusCode::UNAUTHORIZED,
                    "nope",
                )),
                state: Arc::new(()),
            }),
            service: GateService::new(),
        };

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let res = match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(Ok(res)) => res,
            other => panic!("expected ready response, got {other:?}"),
        };

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn unauthenticated_missing_request_returns_internal_error() {
        let mut fut = RequireFuture {
            state: RequireFutureState::CheckingUser {
                request: Box::new(None),
                decision_future: Box::pin(async { Decision::Unauthenticated }),
            },
            inner: Arc::new(RequireState {
                decision: Arc::new(DefaultAccess::<TestBackend, ()>::default()),
                unauthorized: Arc::new(SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope")),
                unauthenticated: Arc::new(SimpleResponseHandler::text(
                    StatusCode::UNAUTHORIZED,
                    "nope",
                )),
                state: Arc::new(()),
            }),
            service: GateService::new(),
        };

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let res = match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Ready(Ok(res)) => res,
            other => panic!("expected ready response, got {other:?}"),
        };

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

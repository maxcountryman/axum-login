use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::http::{self, Request, Response};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{
    service::{CookieController, PlaintextCookie},
    Session, SessionManager, SessionManagerLayer, SessionStore,
};
use tracing::Instrument;

use crate::{AuthSession, AuthUser, AuthnBackend};

/// A middleware that provides [`AuthSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct AuthManager<S, Backend: AuthnBackend> {
    inner: S,
    backend: Backend,
    data_key: &'static str,
}

impl<S, Backend: AuthnBackend> AuthManager<S, Backend> {
    /// Create a new [`AuthManager`] with the provided access controller.
    pub fn new(inner: S, backend: Backend, data_key: &'static str) -> Self {
        Self {
            inner,
            backend,
            data_key,
        }
    }
}

impl<ReqBody, ResBody, S, Backend> Service<Request<ReqBody>> for AuthManager<S, Backend>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send,
    Backend: AuthnBackend + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let span = tracing::info_span!("call", user.id = tracing::field::Empty);

        let backend = self.backend.clone();
        let data_key = self.data_key;

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(
            async move {
                let Some(session) = req.extensions().get::<Session>().cloned() else {
                    tracing::error!("session not found in request extensions");
                    let mut res = Response::default();
                    *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                    return Ok(res);
                };

                let auth_session = match AuthSession::from_session(session, backend, data_key).await
                {
                    Ok(auth_session) => auth_session,
                    Err(err) => {
                        tracing::error!(
                            err = %err,
                            "could not create auth session from session"
                        );
                        let mut res = Response::default();
                        *res.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(res);
                    }
                };

                if let Some(ref user) = auth_session.user {
                    tracing::Span::current().record("user.id", user.id().to_string());
                }

                req.extensions_mut().insert(auth_session);

                inner.call(req).await
            }
            .instrument(span),
        )
    }
}

/// A layer for providing [`AuthSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct AuthManagerLayer<
    Backend: AuthnBackend,
    Sessions: SessionStore,
    C: CookieController = PlaintextCookie,
> {
    backend: Backend,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: &'static str,
}

impl<Backend: AuthnBackend, Sessions: SessionStore, C: CookieController>
    AuthManagerLayer<Backend, Sessions, C>
{
    /// Create a new [`AuthManagerLayer`] with the provided access controller.
    pub(crate) fn new(
        backend: Backend,
        data_key: &'static str,
        session_manager_layer: SessionManagerLayer<Sessions, C>,
    ) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key,
        }
    }
}

impl<S, Backend: AuthnBackend, Sessions: SessionStore, C: CookieController> Layer<S>
    for AuthManagerLayer<Backend, Sessions, C>
{
    type Service = CookieManager<SessionManager<AuthManager<S, Backend>, Sessions, C>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = AuthManager {
            inner,
            backend: self.backend.clone(),
            data_key: self.data_key,
        };

        self.session_manager_layer.layer(login_manager)
    }
}

/// Builder for the [`AuthManagerLayer`].
#[derive(Debug, Clone)]
pub struct AuthManagerLayerBuilder<
    Backend: AuthnBackend,
    Sessions: SessionStore,
    C: CookieController = PlaintextCookie,
> {
    backend: Backend,
    session_manager_layer: SessionManagerLayer<Sessions, C>,
    data_key: Option<&'static str>,
}

impl<Backend: AuthnBackend, Sessions: SessionStore, C: CookieController>
    AuthManagerLayerBuilder<Backend, Sessions, C>
{
    /// Create a new [`AuthManagerLayerBuilder`] with the provided access
    /// controller.
    pub fn new(backend: Backend, session_manager_layer: SessionManagerLayer<Sessions, C>) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key: None,
        }
    }

    /// Configure the `data_key` optional property of the builder. If not
    /// configured it will default to "axum-login.data".
    pub fn with_data_key(
        mut self,
        data_key: &'static str,
    ) -> AuthManagerLayerBuilder<Backend, Sessions, C> {
        self.data_key = Some(data_key);
        self
    }

    /// Build the [`AuthManagerLayer`].
    pub fn build(self) -> AuthManagerLayer<Backend, Sessions, C> {
        AuthManagerLayer::new(
            self.backend,
            self.data_key.unwrap_or("axum-login.data"),
            self.session_manager_layer,
        )
    }
}

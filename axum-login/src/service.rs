use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::http::{Request, Response};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{Session, SessionManager, SessionManagerLayer, SessionStore};

use crate::{AuthSession, AuthnBackend};

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
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Send,
    Backend: AuthnBackend + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let backend = self.backend.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let data_key = self.data_key;

        Box::pin(async move {
            let session = req
                .extensions()
                .get::<Session>()
                .cloned()
                .expect("Requests should have a `Session` extension via tower-sessions.");

            let auth_session =
                AuthSession::from_session(session.clone(), backend, data_key).await?;

            req.extensions_mut().insert(auth_session);

            inner.call(req).await.map_err(Into::into)
        })
    }
}

/// A layer for providing [`AuthSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct AuthManagerLayer<Backend: AuthnBackend, Sessions: SessionStore> {
    backend: Backend,
    session_manager_layer: SessionManagerLayer<Sessions>,
    data_key: &'static str,
}

impl<Backend: AuthnBackend, Sessions: SessionStore> AuthManagerLayer<Backend, Sessions> {
    /// Create a new [`AuthManagerLayer`] with the provided access controller.
    pub(crate) fn new(
        backend: Backend,
        data_key: &'static str,
        session_manager_layer: SessionManagerLayer<Sessions>,
    ) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key,
        }
    }
}

impl<S, Backend: AuthnBackend, Sessions: SessionStore> Layer<S>
    for AuthManagerLayer<Backend, Sessions>
{
    type Service = CookieManager<SessionManager<AuthManager<S, Backend>, Sessions>>;

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
pub struct AuthManagerLayerBuilder<Backend: AuthnBackend, Sessions: SessionStore> {
    backend: Backend,
    session_manager_layer: SessionManagerLayer<Sessions>,
    data_key: Option<&'static str>,
}

impl<Backend: AuthnBackend, Sessions: SessionStore> AuthManagerLayerBuilder<Backend, Sessions> {
    /// Create a new [`AuthManagerLayerBuilder`] with the provided access controller.
    pub fn new(backend: Backend, session_manager_layer: SessionManagerLayer<Sessions>) -> Self {
        Self {
            backend,
            session_manager_layer,
            data_key: None,
        }
    }

    /// Configure the `data_key` optional property of the builder. If not configured it will default to "axum-login.data".
    pub fn with_data_key(
        mut self,
        data_key: &'static str,
    ) -> AuthManagerLayerBuilder<Backend, Sessions> {
        self.data_key = Some(data_key);
        self
    }

    /// Build the [`AuthManagerLayer`].
    pub fn build(self) -> AuthManagerLayer<Backend, Sessions> {
        AuthManagerLayer::new(
            self.backend,
            self.data_key.unwrap_or("axum-login.data"),
            self.session_manager_layer,
        )
    }
}

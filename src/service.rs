use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Request, Response};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{Session, SessionManager, SessionManagerLayer, SessionStore};

use crate::{AccessController, LoginSession};

/// A middleware that provides [`Auth`] as a request extension.
#[derive(Debug, Clone)]
pub struct LoginManager<S, Controller: AccessController> {
    inner: S,
    access_controller: Controller,
}

impl<S, Controller: AccessController> LoginManager<S, Controller> {
    /// Create a new [`LoginManager`] with the provided access controller.
    pub fn new(inner: S, access_controller: Controller) -> Self {
        Self {
            inner,
            access_controller,
        }
    }
}

impl<ReqBody, ResBody, S, Controller> Service<Request<ReqBody>> for LoginManager<S, Controller>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Send,
    Controller: AccessController,
{
    type Response = S::Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let access_controller = self.access_controller.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let session = req
                .extensions()
                .get::<Session>()
                .cloned()
                .expect("Something has gone wrong with tower-sessions.");

            let login_session =
                LoginSession::from_session(session.clone(), access_controller).await?;

            req.extensions_mut().insert(login_session);

            inner.call(req).await.map_err(Into::into)
        })
    }
}

/// A layer for providing [`Auth`] as a request extension.
#[derive(Debug, Clone)]
pub struct LoginManagerLayer<Controller: AccessController, Sessions: SessionStore> {
    access_controller: Controller,
    session_manager_layer: SessionManagerLayer<Sessions>,
}

impl<Controller: AccessController, Sessions: SessionStore> LoginManagerLayer<Controller, Sessions> {
    /// Create a new [`LoginManagerLayer`] with the provided access controller.
    pub fn new(
        access_controller: Controller,
        session_manager_layer: SessionManagerLayer<Sessions>,
    ) -> Self {
        Self {
            access_controller,
            session_manager_layer,
        }
    }
}

impl<S, Controller: AccessController, Sessions: SessionStore> Layer<S>
    for LoginManagerLayer<Controller, Sessions>
{
    type Service = CookieManager<SessionManager<LoginManager<S, Controller>, Sessions>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = LoginManager {
            inner,
            access_controller: self.access_controller.clone(),
        };

        self.session_manager_layer.layer(login_manager)
    }
}

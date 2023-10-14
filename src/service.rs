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

use crate::{Auth, UserStore};

/// A middleware that provides [`Auth`] as a request extension.
#[derive(Debug, Clone)]
pub struct LoginManager<S, Users: UserStore> {
    inner: S,
    user_store: Users,
}

impl<S, Users: UserStore> LoginManager<S, Users> {
    /// Create a new [`LoginManager`] with the provided user store..
    pub fn new(inner: S, user_store: Users) -> Self {
        Self { inner, user_store }
    }
}

impl<ReqBody, ResBody, S, Users> Service<Request<ReqBody>> for LoginManager<S, Users>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Send,
    Users: UserStore,
{
    type Response = S::Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let user_store = self.user_store.clone();

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move {
            let session = req
                .extensions()
                .get::<Session>()
                .cloned()
                .expect("Something has gone wrong with tower-sessions.");

            let auth = Auth::from_session(session.clone(), user_store).await?;

            req.extensions_mut().insert(auth);

            inner.call(req).await.map_err(Into::into)
        })
    }
}

/// A layer for providing [`Auth`] as a request extension.
#[derive(Debug, Clone)]
pub struct LoginManagerLayer<Users: UserStore, Sessions: SessionStore> {
    user_store: Users,
    session_manager_layer: SessionManagerLayer<Sessions>,
}

impl<Users: UserStore, Sessions: SessionStore> LoginManagerLayer<Users, Sessions> {
    /// Create a new [`LoginManagerLayer`] with the provided user store.
    pub fn new(user_store: Users, session_manager_layer: SessionManagerLayer<Sessions>) -> Self {
        Self {
            user_store,
            session_manager_layer,
        }
    }
}

impl<S, Users: UserStore, Sessions: SessionStore> Layer<S> for LoginManagerLayer<Users, Sessions> {
    type Service = CookieManager<SessionManager<LoginManager<S, Users>, Sessions>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = LoginManager {
            inner,
            user_store: self.user_store.clone(),
        };

        self.session_manager_layer.layer(login_manager)
    }
}

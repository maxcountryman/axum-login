use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{Request, Response};
use serde::{Deserialize, Serialize};
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{
    session::SessionError, Session, SessionManager, SessionManagerLayer, SessionStore,
};

use crate::UserStore;

#[derive(thiserror::Error)]
pub enum AuthError<Users: UserStore> {
    #[error(transparent)]
    Session(SessionError),

    #[error(transparent)]
    Users(Users::Error),
}

impl<Users: UserStore> Debug for AuthError<Users> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Session(err) => write!(f, "{:?}", err)?,
            AuthError::Users(err) => write!(f, "{:?}", err)?,
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthData<UserId> {
    user_id: Option<UserId>,
}

impl<UserId> Default for AuthData<UserId>
where
    UserId: Clone,
{
    fn default() -> Self {
        Self { user_id: None }
    }
}

#[derive(Debug, Clone)]
pub struct Auth<Users: UserStore> {
    pub user: Option<Users::User>,
    pub user_store: Users,
    auth_data: AuthData<Users::UserId>,
    session: Session,
}

impl<Users: UserStore> Auth<Users> {
    const AUTH_DATA_KEY: &'static str = "axum-login/auth-data";

    pub async fn login(&mut self, user_id: &Users::UserId) -> Result<(), AuthError<Users>> {
        if let Some(user) = self
            .user_store
            .load(user_id)
            .await
            .map_err(AuthError::Users)?
        {
            self.user = Some(user);
            self.session.cycle_id(); // Session-fixation mitigation.
            self.update_session(|mut auth_data| {
                auth_data.user_id = Some(user_id.clone());
                auth_data
            })
            .map_err(AuthError::Session)?;
        };

        Ok(())
    }

    pub fn logout(&mut self) -> Result<(), AuthError<Users>> {
        self.session.flush();
        self.auth_data = AuthData::default();

        Ok(())
    }

    fn update_session<F>(&mut self, data_updater: F) -> Result<(), SessionError>
    where
        F: Fn(AuthData<Users::UserId>) -> AuthData<Users::UserId>,
    {
        let mut current_value: AuthData<_> =
            self.session.get(Self::AUTH_DATA_KEY)?.unwrap_or_default();

        while let Ok(false) = self.session.replace_if_equal(
            Self::AUTH_DATA_KEY,
            current_value.clone(),
            data_updater(current_value.clone()),
        ) {
            current_value = self.session.get(Self::AUTH_DATA_KEY)?.unwrap_or_default()
        }

        self.auth_data = current_value;

        Ok(())
    }

    async fn from_session(session: Session, user_store: Users) -> Result<Self, AuthError<Users>> {
        let auth_data = match session.get(Self::AUTH_DATA_KEY) {
            Ok(Some(auth_data)) => auth_data,

            Ok(None) => {
                let auth_data = AuthData::default();
                session
                    .insert(Self::AUTH_DATA_KEY, auth_data.clone())
                    .map_err(AuthError::Session)?;
                auth_data
            }

            Err(err) => return Err(AuthError::Session(err)),
        };

        let user = if let Some(ref user_id) = auth_data.user_id {
            user_store.load(user_id).await.map_err(AuthError::Users)?
        } else {
            None
        };

        Ok(Self {
            user,
            auth_data,
            user_store,
            session,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoginManager<S, Users: UserStore> {
    inner: S,
    user_store: Users,
}

impl<S, Users: UserStore> LoginManager<S, Users> {
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

#[derive(Debug, Clone)]
pub struct LoginManagerLayer<Users: UserStore, Sessions: SessionStore> {
    user_store: Users,
    session_manager_layer: SessionManagerLayer<Sessions>,
}

impl<Users: UserStore, Sessions: SessionStore> LoginManagerLayer<Users, Sessions> {
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

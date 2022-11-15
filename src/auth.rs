use std::{
    marker::PhantomData,
    task::{Context, Poll},
};

use axum::{
    body::{BoxBody, HttpBody},
    extract::{FromRequest, RequestParts},
    http::{self, Request},
    response::Response,
    Extension,
};
use axum_sessions::SessionHandle;
use futures::future::BoxFuture;
use ring::hmac::{Key, HMAC_SHA512};
use tower::{Layer, Service};
use tower_http::auth::AuthorizeRequest;

use crate::{extractors::AuthContext, user_store::UserStore, AuthUser};

/// Layer that provides session-based authentication via [`AuthContext`].
#[derive(Debug, Clone)]
pub struct AuthLayer<User, Store, Role = ()> {
    store: Store,
    key: Key,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

impl<User, Store, Role> AuthLayer<User, Store, Role>
where
    User: AuthUser<Role>,
    Role: Clone + Send + Sync + 'static,
    Store: UserStore<Role, User = User>,
{
    /// Creates a layer which will attach the [`AuthContext`] and `User` to
    /// requests via extensions.
    ///
    /// Note that the `secret` is used to derive a key for HMAC signing. For
    /// security reasons, this value **must** be securely generated.
    pub fn new(store: Store, secret: &[u8]) -> Self {
        Self {
            store,
            key: Key::new(HMAC_SHA512, secret),
            _user_type: PhantomData,
            _role_type: PhantomData,
        }
    }
}

impl<User, Store, Inner, Role> Layer<Inner> for AuthLayer<User, Store, Role>
where
    Role: Clone + Send + Sync + 'static,
    User: AuthUser<Role>,
    Store: UserStore<Role>,
{
    type Service = Auth<User, Store, Inner, Role>;

    fn layer(&self, inner: Inner) -> Self::Service {
        Auth {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Auth<User, Store, Inner, Role = ()> {
    inner: Inner,
    layer: AuthLayer<User, Store, Role>,
}

impl<User, Store, Inner, ReqBody, Role> Service<Request<ReqBody>> for Auth<User, Store, Inner, Role>
where
    Role: Clone + Send + Sync + 'static,
    User: AuthUser<Role>,
    Store: UserStore<Role, User = User>,
    Inner: Service<Request<ReqBody>, Response = Response> + Clone + Send + 'static,
    ReqBody: Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = Inner::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let auth_layer = self.layer.clone();
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let mut request_parts = RequestParts::new(request);

            let Extension(session_handle): Extension<SessionHandle> =
                Extension::from_request(&mut request_parts)
                    .await
                    .expect("Session extension missing. Is the session layer installed?");

            let mut request = request_parts.try_into_request().expect("body extracted");

            let mut auth_cx = AuthContext::new(session_handle, auth_layer.store, auth_layer.key);
            match auth_cx.get_user().await {
                Ok(user) => {
                    auth_cx.current_user = user;

                    request.extensions_mut().insert(auth_cx.clone());
                    request.extensions_mut().insert(auth_cx.current_user);

                    inner.call(request).await
                }

                Err(err) => {
                    tracing::error!("Could not get user: {:?}", err);
                    let response = Response::builder()
                        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Default::default())
                        .unwrap();
                    Ok(response)
                }
            }
        })
    }
}

/// Type that performs login authorization.
///
/// See [`RequireAuthorizationLayer::login`] for more details.
pub struct Login<User, ResBody, Role = ()> {
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
    _body_type: PhantomData<fn() -> ResBody>,
}

impl<User, ResBody, Role> Clone for Login<User, ResBody, Role> {
    fn clone(&self) -> Self {
        Self {
            _user_type: PhantomData,
            _role_type: PhantomData,
            _body_type: PhantomData,
        }
    }
}

impl<User, ReqBody, ResBody, Role> AuthorizeRequest<ReqBody> for Login<User, ResBody, Role>
where
    Role: Clone + Send + Sync + 'static,
    User: AuthUser<Role>,
    ResBody: HttpBody + Default,
{
    type ResponseBody = ResBody;

    fn authorize(
        &mut self,
        request: &mut Request<ReqBody>,
    ) -> Result<(), Response<Self::ResponseBody>> {
        let user = request
            .extensions()
            .get::<Option<User>>()
            .expect("Auth extension missing. Is the auth layer installed?");
        if let Some(user) = user {
            let user = user.clone();
            request.extensions_mut().insert(user);

            Ok(())
        } else {
            let unauthorized_response = Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap();

            Err(unauthorized_response)
        }
    }
}

/// A wrapper around [`tower_http::auth::RequireAuthorizationLayer`] which
/// provides login authorization.
pub struct RequireAuthorizationLayer<User, Role = ()>(User, Role);

impl<User, Role> RequireAuthorizationLayer<User, Role>
where
    Role: Clone + Send + Sync + 'static,
    User: AuthUser<Role>,
{
    /// Authorizes requests by requiring a logged in user, otherwise it rejects
    /// with [`http::StatusCode::UNAUTHORIZED`].
    pub fn login<ResBody>(
    ) -> tower_http::auth::RequireAuthorizationLayer<Login<User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::RequireAuthorizationLayer::custom(Login::<_, _, _> {
            _user_type: PhantomData,
            _role_type: PhantomData,
            _body_type: PhantomData,
        })
    }
}

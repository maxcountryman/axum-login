use std::{
    marker::PhantomData,
    ops::{RangeBounds, RangeFull},
    task::{Context, Poll},
};

use axum::{
    body::HttpBody,
    extract::{FromRequest, RequestParts},
    http::{self, Request},
    response::Response,
    Extension,
};
use axum_sessions::SessionHandle;
use dyn_clone::DynClone;
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
    Role: PartialOrd + PartialOrd + PartialEq + Clone + Send + Sync + 'static,
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
    Role: PartialOrd + PartialOrd + PartialEq + Clone + Send + Sync + 'static,
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

impl<User, Store, Role, Inner, ReqBody, ResBody> Service<Request<ReqBody>>
    for Auth<User, Store, Inner, Role>
where
    User: AuthUser<Role>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    Store: UserStore<Role, User = User>,
    Inner: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    ResBody: Default + Send + 'static,
    ReqBody: Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Inner::Response;
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

trait RoleBounds<Role>: DynClone + Send + Sync {
    fn contains(&self, role: Option<Role>) -> bool;
}

impl<T, Role> RoleBounds<Role> for T
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    T: RangeBounds<Role> + Clone + Send + Sync,
{
    fn contains(&self, role: Option<Role>) -> bool {
        if let Some(role) = role {
            RangeBounds::contains(self, &role)
        } else {
            role.is_none()
        }
    }
}

/// Type that performs login authorization.
///
/// See [`RequireAuthorizationLayer::login`] for more details.
pub struct Login<User, ResBody, Role = ()>
where
    Role: PartialOrd + PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    role_bounds: Box<dyn RoleBounds<Role>>,
    _user_type: PhantomData<User>,
    _body_type: PhantomData<fn() -> ResBody>,
}

impl<User, ResBody, Role> Clone for Login<User, ResBody, Role>
where
    Role: PartialOrd + PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            role_bounds: dyn_clone::clone_box(&*self.role_bounds),
            _user_type: PhantomData,
            _body_type: PhantomData,
        }
    }
}

impl<User, ReqBody, ResBody, Role> AuthorizeRequest<ReqBody> for Login<User, ResBody, Role>
where
    Role: PartialOrd + PartialOrd + PartialEq + Clone + Send + Sync + 'static,
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

        match user {
            Some(user) if self.role_bounds.contains(user.get_role()) => {
                let user = user.clone();
                request.extensions_mut().insert(user);

                Ok(())
            }

            _ => {
                let unauthorized_response = Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(Default::default())
                    .unwrap();

                Err(unauthorized_response)
            }
        }
    }
}

/// A wrapper around [`tower_http::auth::RequireAuthorizationLayer`] which
/// provides login authorization.
pub struct RequireAuthorizationLayer<User, Role = ()>(User, Role);

impl<User, Role> RequireAuthorizationLayer<User, Role>
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
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
            role_bounds: Box::new(..),
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }

    /// Authorizes requests by requiring a logged in user to have a specific
    /// role, otherwise it rejects
    /// with [`http::StatusCode::UNAUTHORIZED`].
    pub fn login_with_role<ResBody>(
        role_bounds: impl RangeBounds<Role> + Clone + Send + Sync + 'static,
    ) -> tower_http::auth::RequireAuthorizationLayer<Login<User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::RequireAuthorizationLayer::custom(Login::<_, _, _> {
            role_bounds: Box::new(role_bounds),
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::http::{Request, Response};
    use http::{
        header::{COOKIE, SET_COOKIE},
        StatusCode,
    };
    use hyper::Body;
    use rand::Rng;
    use tokio::sync::RwLock;
    use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

    use crate::{
        axum_sessions::{async_session::MemoryStore, SessionLayer},
        extractors::AuthContext,
        memory_store::MemoryStore as AuthMemoryStore,
        AuthLayer, AuthUser,
    };

    #[derive(Debug, Default, Clone)]
    struct User {
        id: usize,
        password_hash: String,
    }

    impl User {
        fn get_rusty_user() -> Self {
            Self {
                id: 1,
                ..Default::default()
            }
        }
    }

    impl AuthUser for User {
        fn get_id(&self) -> String {
            format!("{}", self.id)
        }

        fn get_password_hash(&self) -> String {
            self.password_hash.clone()
        }
    }

    type Auth = AuthContext<User, AuthMemoryStore<User>>;

    #[tokio::test]
    async fn logs_user_in() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        let mut request = Request::get("/protected").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let mut request = Request::get("/login").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let mut request = Request::get("/protected").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    async fn login(mut req: Request<Body>) -> Result<Response<Body>, BoxError> {
        if req.uri() == "/login" {
            let auth = req.extensions_mut().get_mut::<Auth>();
            let user = &User::get_rusty_user();
            auth.unwrap().login(user).await.unwrap();
        }

        if req.uri() == "/protected" {
            let auth = req.extensions().get::<Auth>();
            let auth_user = auth.unwrap().current_user.clone();
            if auth_user.is_none() {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Default::default())
                    .unwrap());
            }
        }

        Ok(Response::new(req.into_body()))
    }
}

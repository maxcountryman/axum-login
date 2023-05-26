use std::{
    borrow::Cow,
    marker::PhantomData,
    ops::RangeBounds,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    body::HttpBody,
    http::{self, Request},
    response::Response,
    Extension, RequestExt,
};
use axum_sessions::SessionHandle;
use dyn_clone::DynClone;
use futures::future::BoxFuture;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use ring::hmac::{Key, HMAC_SHA512};
use serde::{de::DeserializeOwned, Serialize};
use tower::{Layer, Service};
use tower_http::auth::AsyncAuthorizeRequest;

use crate::{extractors::AuthContext, user_store::UserStore, AuthUser};

// from https://github.com/tokio-rs/axum/blob/7219fd8df520d295faa42b59f77e25ca2818b6b1/axum-extra/src/lib.rs#L91
// which in turn is from https://github.com/servo/rust-url/blob/master/url/src/parser.rs
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');
const PATH: &AsciiSet = &FRAGMENT.add(b'#').add(b'?').add(b'{').add(b'}');
const PATH_SEGMENT: &AsciiSet = &PATH.add(b'/').add(b'%');

#[derive(Clone)]
struct AuthState<Store, UserId, User, Role = ()> {
    key: Key,
    store: Store,
    _user_id_type: PhantomData<UserId>,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

/// Layer that provides session-based authentication via [`AuthContext`].
#[derive(Clone)]
pub struct AuthLayer<Store, UserId, User, Role = ()> {
    state: AuthState<Store, UserId, User, Role>,
}

impl<Store, UserId, User, Role> AuthLayer<Store, UserId, User, Role>
where
    Store: UserStore<UserId, Role, User = User>,
    User: AuthUser<UserId, Role>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    /// Creates a layer which will attach the [`AuthContext`] and `User` to
    /// requests via extensions.
    ///
    /// Note that the `secret` is used to derive a key for HMAC signing. For
    /// security reasons, this value **must** be securely generated.
    pub fn new(store: Store, secret: &[u8]) -> Self {
        let state = AuthState {
            store,
            key: Key::new(HMAC_SHA512, secret),
            _user_id_type: PhantomData,
            _user_type: PhantomData,
            _role_type: PhantomData,
        };

        Self { state }
    }
}

impl<S, Store, UserId, User, Role> Layer<S> for AuthLayer<Store, UserId, User, Role>
where
    Store: UserStore<UserId, Role>,
    UserId: Clone,
    User: AuthUser<UserId, Role>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    type Service = AuthService<S, Store, UserId, User, Role>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService<S, Store, UserId, User, Role = ()> {
    inner: S,
    state: AuthState<Store, UserId, User, Role>,
}

impl<S, ReqBody, ResBody, Store, UserId, User, Role> Service<Request<ReqBody>>
    for AuthService<S, Store, UserId, User, Role>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    Store: UserStore<UserId, Role, User = User>,
    UserId: Clone + Send + Sync + Serialize + DeserializeOwned + 'static,
    User: AuthUser<UserId, Role>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let state = self.state.clone();
        let inner = self.inner.clone();

        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let Extension(session_handle): Extension<SessionHandle> = request
                .extract_parts()
                .await
                .expect("Session extension missing. Is the session layer installed?");

            let mut auth_cx = AuthContext::new(session_handle, state.store, state.key);
            match auth_cx.get_user().await {
                Ok(user) => {
                    auth_cx.current_user = user;

                    request.extensions_mut().insert(auth_cx.clone());
                    request
                        .extensions_mut()
                        .insert(auth_cx.current_user.clone());
                    if let Some(current_user) = auth_cx.current_user {
                        request.extensions_mut().insert(current_user);
                    }

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
    Role: PartialOrd + PartialEq,
    T: RangeBounds<Role> + Clone + Send + Sync,
{
    fn contains(&self, role: Option<Role>) -> bool {
        if let Some(role) = role {
            RangeBounds::contains(self, &role)
        } else {
            role.is_some()
        }
    }
}

/// Type that performs login authorization.
///
/// See [`RequireAuthorizationLayer::login`] for more details.
pub struct Login<UserId, User, ResBody, Role = ()> {
    login_url: Option<Arc<Cow<'static, str>>>,
    redirect_field_name: Option<Arc<Cow<'static, str>>>,
    role_bounds: Option<Box<dyn RoleBounds<Role>>>,
    _user_id_type: PhantomData<UserId>,
    _user_type: PhantomData<User>,
    _body_type: PhantomData<fn() -> ResBody>,
}

impl<UserId, User, ResBody, Role> Clone for Login<UserId, User, ResBody, Role> {
    fn clone(&self) -> Self {
        Self {
            login_url: self.login_url.clone(),
            redirect_field_name: self.redirect_field_name.clone(),
            role_bounds: self
                .role_bounds
                .as_ref()
                .map(|rb| dyn_clone::clone_box(&**rb)),
            _user_id_type: PhantomData,
            _user_type: PhantomData,
            _body_type: PhantomData,
        }
    }
}

impl<UserId, User, ReqBody, ResBody, Role> AsyncAuthorizeRequest<ReqBody>
    for Login<UserId, User, ResBody, Role>
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role>,
    ResBody: HttpBody + Default,
    UserId: Send + 'static,
    ReqBody: Send + 'static,
{
    type ResponseBody = ResBody;
    type RequestBody = ReqBody;
    type Future =
        BoxFuture<'static, Result<Request<Self::RequestBody>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let role_bounds = self
            .role_bounds
            .as_ref()
            .map(|rb| dyn_clone::clone_box(&**rb));
        let login_url = self.login_url.clone();
        let redirect_field_name = self.redirect_field_name.clone();
        Box::pin(async move {
            let user = request
                .extensions()
                .get::<Option<User>>()
                .expect("Auth extension missing. Is the auth layer installed?");

            match user {
                Some(user)
                    if role_bounds
                        .map(|rb| rb.contains(user.get_role()))
                        .unwrap_or(true) =>
                {
                    let user = user.clone();
                    request.extensions_mut().insert(user);

                    Ok(request)
                }
                _ => {
                    let unauthorized_response = if let Some(ref login_url) = login_url {
                        let url: Cow<'static, str> = if let Some(ref next) = redirect_field_name {
                            format!(
                                "{login_url}?{next}={}",
                                utf8_percent_encode(request.uri().path(), PATH_SEGMENT)
                            )
                            .into()
                        } else {
                            login_url.as_ref().clone()
                        };
                        Response::builder()
                            .status(http::StatusCode::TEMPORARY_REDIRECT)
                            .header(http::header::LOCATION, url.as_ref())
                            .body(Default::default())
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(http::StatusCode::UNAUTHORIZED)
                            .body(Default::default())
                            .unwrap()
                    };

                    Err(unauthorized_response)
                }
            }
        })
    }
}

/// A wrapper around [`tower_http::auth::AsyncRequireAuthorizationLayer`] which
/// provides login authorization.
pub struct RequireAuthorizationLayer<UserId, User, Role = ()>(UserId, User, Role);

impl<UserId, User, Role> RequireAuthorizationLayer<UserId, User, Role>
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role>,
{
    /// Authorizes requests by requiring a logged in user, otherwise it rejects
    /// with [`http::StatusCode::UNAUTHORIZED`].
    pub fn login<ResBody>(
    ) -> tower_http::auth::AsyncRequireAuthorizationLayer<Login<UserId, User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::AsyncRequireAuthorizationLayer::new(Login::<_, _, _, _> {
            login_url: None,
            redirect_field_name: None,
            role_bounds: None,
            _user_id_type: PhantomData,
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }

    /// Authorizes requests by requiring a logged in user to have a specific
    /// range of roles, otherwise it rejects with
    /// [`http::StatusCode::UNAUTHORIZED`].
    pub fn login_with_role<ResBody>(
        role_bounds: impl RangeBounds<Role> + Clone + Send + Sync + 'static,
    ) -> tower_http::auth::AsyncRequireAuthorizationLayer<Login<UserId, User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::AsyncRequireAuthorizationLayer::new(Login::<_, _, _, _> {
            login_url: None,
            redirect_field_name: None,
            role_bounds: Some(Box::new(role_bounds)),
            _user_id_type: PhantomData,
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }

    /// Authorizes requests by requiring a logged in user, otherwise it
    /// redirects to the provided login URL.
    ///
    /// If `redirect_field_name` is set to a value, the login page will receive
    /// the path it was redirected from in the URI query part. For example,
    /// attempting to visit a protected path `/protected` would redirect you
    /// to `/login?next=/protected` allowing you to know how to return the
    /// visitor to their requested page.
    pub fn login_or_redirect<ResBody>(
        login_url: Arc<Cow<'static, str>>,
        redirect_field_name: Option<Arc<Cow<'static, str>>>,
    ) -> tower_http::auth::AsyncRequireAuthorizationLayer<Login<UserId, User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::AsyncRequireAuthorizationLayer::new(Login::<_, _, _, _> {
            login_url: Some(login_url),
            redirect_field_name,
            role_bounds: None,
            _user_id_type: PhantomData,
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }

    /// Authorizes requests by requiring a logged in user to have a specific
    /// range of roles, otherwise it redirects to the
    /// provided login URL.
    ///
    /// If `redirect_field_name` is set to a value, the login page will receive
    /// the path it was redirected from in the URI query part. For example,
    /// attempting to visit a protected path `/protected` would redirect you
    /// to `/login?next=/protected` allowing you to know how to return the
    /// visitor to their requested page.
    pub fn login_with_role_or_redirect<ResBody>(
        role_bounds: impl RangeBounds<Role> + Clone + Send + Sync + 'static,
        login_url: Arc<Cow<'static, str>>,
        redirect_field_name: Option<Arc<Cow<'static, str>>>,
    ) -> tower_http::auth::AsyncRequireAuthorizationLayer<Login<UserId, User, ResBody, Role>>
    where
        ResBody: HttpBody + Default,
    {
        tower_http::auth::AsyncRequireAuthorizationLayer::new(Login::<_, _, _, _> {
            login_url: Some(login_url),
            redirect_field_name,
            role_bounds: Some(Box::new(role_bounds)),
            _user_id_type: PhantomData,
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

    #[derive(Debug, Clone, PartialEq, PartialOrd)]
    enum Role {
        User,
        Admin,
    }

    #[derive(Debug, Default, Clone)]
    struct User {
        id: usize,
        role: Option<Role>,
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

    impl AuthUser<usize, Role> for User {
        fn get_id(&self) -> usize {
            self.id
        }

        fn get_role(&self) -> Option<Role> {
            self.role.clone()
        }

        fn get_password_hash(&self) -> secrecy::SecretVec<u8> {
            secrecy::SecretVec::new(self.password_hash.clone().into())
        }
    }

    type Auth = AuthContext<usize, User, AuthMemoryStore<usize, User>, Role>;
    type RequireAuth = crate::auth::RequireAuthorizationLayer<usize, User, Role>;

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

    #[tokio::test]
    async fn redirects_to_login_url() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        let login_url = Arc::new("/login".into());

        let mut service = ServiceBuilder::new()
            .layer(session_layer.clone())
            .layer(auth_layer.clone())
            .service_fn(login);

        let mut protected_service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .layer(RequireAuth::login_or_redirect(Arc::clone(&login_url), None))
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        let mut request = Request::get("/protected").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers().get(http::header::LOCATION),
            Some(&login_url.as_ref().as_ref().try_into().unwrap())
        );

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
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn redirects_to_login_url_with_next() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        let login_url = Arc::new("/login".into());

        let mut service = ServiceBuilder::new()
            .layer(session_layer.clone())
            .layer(auth_layer.clone())
            .service_fn(login);

        let mut protected_service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .layer(RequireAuth::login_or_redirect(
                Arc::clone(&login_url),
                Some(Arc::new("next".into())),
            ))
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

        let mut request = Request::get("/protected").body(Body::empty()).unwrap();
        request
            .headers_mut()
            .insert(COOKIE, session_cookie.to_owned());
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers().get(http::header::LOCATION),
            Some(
                &format!("{}?next=%2Fprotected", login_url.as_ref())
                    .try_into()
                    .unwrap()
            )
        );

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
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_with_role_or_redirect() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        let login_url = Arc::new("/login".into());

        let mut service = ServiceBuilder::new()
            .layer(session_layer.clone())
            .layer(auth_layer.clone())
            .service_fn(login);

        let mut protected_service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .layer(RequireAuth::login_with_role_or_redirect(
                Role::Admin..,
                Arc::clone(&login_url),
                None,
            ))
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers().get(http::header::LOCATION),
            Some(&login_url.as_ref().as_ref().try_into().unwrap())
        );
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

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
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers().get(http::header::LOCATION),
            Some(&login_url.as_ref().as_ref().try_into().unwrap())
        );
        for (role, status) in [
            (Role::User, StatusCode::TEMPORARY_REDIRECT),
            (Role::Admin, StatusCode::OK),
        ] {
            let mut user = User::get_rusty_user();
            user.role = Some(role);
            store.write().await.insert(user.get_id(), user);

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
            let res = protected_service
                .ready()
                .await
                .unwrap()
                .call(request)
                .await
                .unwrap();
            assert_eq!(res.status(), status);
        }
    }

    #[tokio::test]
    async fn login_with_role() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        let mut service = ServiceBuilder::new()
            .layer(session_layer.clone())
            .layer(auth_layer.clone())
            .service_fn(login);

        let mut protected_service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .layer(RequireAuth::login_with_role(Role::Admin..))
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

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
        let res = protected_service
            .ready()
            .await
            .unwrap()
            .call(request)
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        for (role, status) in [
            (Role::User, StatusCode::UNAUTHORIZED),
            (Role::Admin, StatusCode::OK),
        ] {
            let mut user = User::get_rusty_user();
            user.role = Some(role);
            store.write().await.insert(user.get_id(), user);

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
            let res = protected_service
                .ready()
                .await
                .unwrap()
                .call(request)
                .await
                .unwrap();
            assert_eq!(res.status(), status);
        }
    }

    #[tokio::test]
    async fn user_extensions() {
        let secret = rand::thread_rng().gen::<[u8; 64]>();

        let store = MemoryStore::new();
        let session_layer = SessionLayer::new(store, &secret);

        let store = Arc::new(RwLock::new(HashMap::default()));
        let user = User::get_rusty_user();
        store.write().await.insert(user.get_id(), user);

        let user_store = AuthMemoryStore::new(&store);
        let auth_layer = AuthLayer::new(user_store, &secret);

        async fn login(mut req: Request<Body>) -> Result<Response<Body>, BoxError> {
            if req.uri() == "/login" {
                let auth = req.extensions_mut().get_mut::<Auth>();
                let user = &User::get_rusty_user();
                auth.unwrap().login(user).await.unwrap();
            }

            if req.uri() == "/protected" {
                let optional_auth_user = req.extensions().get::<Option<User>>();
                let invalid_optional_auth_user = match optional_auth_user {
                    Some(None) => true,
                    Some(Some(User { .. })) => false,
                    None => unreachable!(),
                };
                let auth_user = req.extensions().get::<User>();
                let invalid_auth_user = match auth_user {
                    None => true,
                    Some(User { .. }) => false,
                };
                match (invalid_optional_auth_user, invalid_auth_user) {
                    // Verify Option<User> and User extensions match
                    (false, false) => (),
                    (false, true) | (true, false) => unreachable!(),
                    (true, true) => {
                        // Emulate invalid extension by returning INTERNAL_SERVER_ERROR
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Default::default())
                            .unwrap());
                    }
                }
            }

            Ok(Response::new(req.into_body()))
        }

        let mut service = ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_layer)
            .service_fn(login);

        let request = Request::get("/protected").body(Body::empty()).unwrap();
        let res = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let session_cookie = res.headers().get(SET_COOKIE).unwrap().clone();

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
}

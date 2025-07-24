use crate::{url_with_redirect_query, AuthSession, AuthnBackend, AuthzBackend};
use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use std::fmt;
use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_LOGIN_URL: &str = "/signin";
const DEFAULT_REDIRECT_FIELD: &str = "next_uri";
// TODO: I am not sure if the current type implementation of these functions is great.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
//TODO: there is a mess with how to name different handlers and their wrappers
pub type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
pub type RestrictFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;
pub type FallbackFn<T> = Arc<dyn Fn(Request<T>, Uri) -> BoxFuture<'static, Response> + Send + Sync>;

pub struct RequireService<S, B: AuthnBackend, ST: Clone, T> {
    inner: S,
    /// Function used to check user permissions or other requirements
    predicate: PredicateStateFn<B, ST>,
    /// Handler used in case the user fails predicate check
    fallback: FallbackFn<T>,
    /// State of the application
    state: ST,
    restrict: RestrictFn<T>,
}

//umm, manual clone, yes
impl<S, B, ST, T> Clone for RequireService<S, B, ST, T>
where
    S: Clone,
    ST: Clone,
    B: AuthzBackend,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            predicate: self.predicate.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            restrict: self.restrict.clone(),
        }
    }
}

impl<T, S, B, ST> Service<Request<T>> for RequireService<S, B, ST, T>
where
    S: Service<Request<T>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: AuthnBackend + AuthzBackend + Clone + Send + 'static,
    ST: Clone + Send + 'static,
    T: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<T>) -> Self::Future {
        let original_uri = req.extensions().get::<OriginalUri>().cloned();
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();

        let fallback = self.fallback.clone();
        let predicate = self.predicate.clone();
        let restrict = self.restrict.clone();
        let state = self.state.clone();

        // This should help
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            match (original_uri, auth_session) {
                (
                    _,
                    Some(AuthSession {
                        user: Some(user),
                        backend,
                        ..
                    }),
                ) => {
                    // Only enter here if user is Some(...)
                    if predicate(backend, user.clone(), state).await {
                        // Authorized
                        let response = inner.call(req).await?;
                        Ok(response)
                    } else {
                        // Restricted
                        let response = restrict(req).await;
                        Ok(response)
                    }
                }
                (Some(original_uri), Some(_auth_session)) => {
                    // No user in session, use fallback
                    let response = fallback(req, original_uri.0).await;
                    Ok(response)
                }
                _ => {
                    // Missing required extensions
                    Ok(axum::response::IntoResponse::into_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        })
    }
}

pub struct Require<B: AuthnBackend, ST = (), T = Body> {
    pub predicate: PredicateStateFn<B, ST>, // Should depend on state availability
    pub restrict: RestrictFn<T>,
    pub fallback: FallbackFn<T>,
    pub state: ST,
}

//umm, manual clone, because of Body
impl<B, ST, T> Clone for Require<B, ST, T>
where
    ST: Clone,
    B: AuthzBackend,
{
    fn clone(&self) -> Self {
        Self {
            predicate: self.predicate.clone(),
            restrict: self.restrict.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
        }
    }
}

impl<S, B, ST, T> Layer<S> for Require<B, ST, T>
where
    B: Clone + AuthzBackend,
    ST: Clone,
{
    type Service = RequireService<S, B, ST, T>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            predicate: self.predicate.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            restrict: self.restrict.clone(),
        }
    }
}

// --- The Builder

//TODO: create Require without state (nullable state)
pub struct RequireBuilder<B: AuthnBackend, ST = (), T = Body> {
    predicate: Option<PredicateStateFn<B, ST>>,
    /// Handler for user lacking permissions
    restrict: Option<RestrictFn<T>>,
    /// Handler for user authentication
    fallback: Option<FallbackFn<T>>,
    /// State to get values dynamically
    state: Option<ST>,
}

pub enum Predicate<B: AuthzBackend, ST> {
    Function(PredicateStateFn<B, ST>),
    Params { permissions: Vec<B::Permission> },
}

impl<B, ST> fmt::Debug for Predicate<B, ST>
where
    B: AuthzBackend,
    B::Permission: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Predicate::Function(_) => f.debug_tuple("Function").field(&"<function>").finish(),
            Predicate::Params { permissions } => f
                .debug_struct("Params")
                .field("permissions", permissions)
                .finish(),
        }
    }
}

impl<B: AuthzBackend, ST> Predicate<B, ST> {
    pub fn from_closure<F, Fut>(f: F) -> Self
    where
        F: Fn(B, B::User, ST) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        Self::Function(Arc::new(move |b, usr, st| Box::pin(f(b, usr, st))))
    }
}

impl<B, ST> From<Predicate<B, ST>> for PredicateStateFn<B, ST>
where
    B: AuthnBackend + AuthzBackend + 'static,
    B::User: 'static,
    B::Permission: Clone,
    ST: Clone + Send + Sync + 'static,
{
    fn from(params: Predicate<B, ST>) -> Self {
        match params {
            Predicate::Function(f) => Arc::new(move |backend, user, state| {
                Box::pin(f(backend, user, state)) as Pin<Box<dyn Future<Output = bool> + Send>>
            }),

            Predicate::Params { permissions, .. } => {
                let permissions = permissions.clone();
                Arc::new(move |backend: B, user: B::User, _state: ST| {
                    let permissions = permissions.clone();
                    Box::pin(async move {
                        let Ok(u_perms) = backend.get_user_permissions(&user).await else {
                            return false;
                        };
                        permissions.iter().any(|perm| u_perms.contains(perm))
                    })
                })
            }
        }
    }
}

pub enum Rstr<T = Body> {
    HandlerFunc(RestrictFn<T>),
    Params {
        i_dunno: Option<String>, //TODO: haven't decided yet what parameters it should have
    },
}
impl<T> fmt::Debug for Rstr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rstr::HandlerFunc(_) => f.debug_tuple("HandlerFunc").field(&"<closure>").finish(),
            Rstr::Params { i_dunno } => f.debug_struct("Params").field("i_dunno", i_dunno).finish(),
        }
    }
}

impl<T> From<Rstr<T>> for RestrictFn<T>
where
    T: Send + 'static,
{
    fn from(handler: Rstr<T>) -> Self {
        match handler {
            Rstr::HandlerFunc(f) => Arc::new(move |req| {
                Box::pin(f(req)) as Pin<Box<dyn Future<Output = Response> + Send>>
            }),

            Rstr::Params { .. } => Arc::new(|_req| {
                Box::pin(async {
                    // TODO: replace with logic using params
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body("TODO".into())
                        .unwrap()
                }) as Pin<Box<dyn Future<Output = Response> + Send>>
            }),
        }
    }
}

impl<T> Rstr<T>
where
    T: Send + 'static,
{
    pub fn from_closure<F, Fut>(f: F) -> Self
    where
        F: Fn(Request<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self::HandlerFunc(Arc::new(move |req| Box::pin(f(req))))
    }
}

pub enum MissingAuthHandlerParams<T = Body> {
    HandlerFunc(FallbackFn<T>),
    Params {
        redirect_field: Option<String>,
        login_url: Option<String>,
    },
}

impl<T> fmt::Debug for MissingAuthHandlerParams<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MissingAuthHandlerParams::HandlerFunc(_) => {
                f.debug_tuple("HandlerFunc").field(&"<closure>").finish()
            }
            MissingAuthHandlerParams::Params {
                redirect_field,
                login_url,
            } => f
                .debug_struct("Params")
                .field("redirect_field", redirect_field)
                .field("login_url", login_url)
                .finish(),
        }
    }
}

impl<T> MissingAuthHandlerParams<T>
where
    T: Send + 'static,
{
    pub fn from_handler<F, Fut>(f: F) -> Self
    where
        F: Fn(Request<T>, Uri) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        MissingAuthHandlerParams::HandlerFunc(Arc::new(move |req, uri| Box::pin(f(req, uri))))
    }
}

impl<T> From<MissingAuthHandlerParams<T>> for FallbackFn<T>
where
    T: Send + 'static,
{
    fn from(params: MissingAuthHandlerParams<T>) -> Self {
        match params {
            MissingAuthHandlerParams::HandlerFunc(f) => Arc::new(move |req, uri| {
                Box::pin(f(req, uri)) as Pin<Box<dyn Future<Output = Response> + Send>>
            }),

            MissingAuthHandlerParams::Params {
                redirect_field,
                login_url,
                ..
            } => {
                let login_url = login_url.unwrap_or(DEFAULT_LOGIN_URL.to_string());
                let redirect_field = redirect_field.unwrap_or(DEFAULT_REDIRECT_FIELD.to_string());

                Arc::new(move |_req, _uri| {
                    // clone before the async block so they're owned in the future
                    let login_url = login_url.clone();
                    let redirect_field = redirect_field.clone();

                    Box::pin(async move {
                        let url =
                            url_with_redirect_query(&login_url, &redirect_field, _uri).unwrap();
                        Response::builder()
                            .status(StatusCode::TEMPORARY_REDIRECT)
                            .header("Location", url.to_string())
                            .body("Redirecting...".into())
                            .unwrap()
                    }) as Pin<Box<dyn Future<Output = Response> + Send>>
                })
            }
        }
    }
}

/// Always return Unauthorized
// impl<T> Default for MissingAuthHandlerParams<T> {
//     fn default() -> Self {
//         Self::HandlerFunc(Arc::new(|_, _| {
//             Box::pin(async {
//                 Response::builder()
//                     .status(StatusCode::UNAUTHORIZED)
//                     .body("Unauthorized".into())
//                     .unwrap()
//             }) as Pin<Box<dyn Future<Output = Response> + Send>>
//         }))
//     }
// }

impl<B: AuthnBackend, ST: Clone, T: 'static + Send> RequireBuilder<B, ST, T>
where
    Arc<
        dyn Fn(
                axum::http::Request<T>,
                Uri,
            ) -> Pin<Box<(dyn Future<Output = Response<Body>> + Send + 'static)>>
            + Send
            + Sync,
    >: From<MissingAuthHandlerParams>,
{
    pub fn new() -> Self {
        Self {
            predicate: None,
            restrict: None,
            fallback: None,
            state: None,
        }
    }

    pub fn predicate(mut self, pred: Predicate<B, ST>) -> RequireBuilder<B, ST, T>
    where
        B: AuthnBackend + AuthzBackend + 'static,
        B::User: 'static,
        B::Permission: Clone,
        ST: Clone + Send + Sync + 'static,
    {
        self.predicate = Some(pred.into());

        self
    }

    /// Custom no auth fallback function, overrides default Unauthorized response
    pub fn fallback(mut self, func: MissingAuthHandlerParams) -> Self {
        self.fallback = Some(func.into());
        self
    }

    /// Custom missing permissions function, overrides default Forbidden response
    pub fn on_restrict(mut self, func: Rstr<T>) -> Self
    where
        T: Send + 'static,
    {
        self.restrict = Some(func.into());
        self
    }

    pub fn state(mut self, state: ST) -> Self {
        self.state = Some(state);
        self
    }
    fn default_fallback() -> FallbackFn<T> {
        Arc::new(|_req, _uri| {
            Box::pin(async {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body("Unauthorized".into())
                    .unwrap()
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }

    fn default_restrict() -> RestrictFn<T> {
        Arc::new(|_req| {
            Box::pin(async {
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body("Forbidden".into())
                    .unwrap()
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }

    /// Always returns True
    fn default_predicat() -> PredicateStateFn<B, ST> {
        Arc::new(|_backend: B, _user: B::User, _state: ST| {
            Box::pin(ready(true)) as Pin<Box<dyn Future<Output = bool> + Send>>
        })
    }

    pub fn build(self) -> Require<B, ST, T> {
        let predicate = self.predicate.unwrap_or_else(Self::default_predicat);

        let fallback = self.fallback.unwrap_or_else(Self::default_fallback);
        let perm_fallback = self.restrict.unwrap_or_else(Self::default_restrict);

        Require {
            predicate,
            restrict: perm_fallback,
            fallback,
            state: self
                .state
                .expect("State is required. Use .state() or contribute to library"),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use axum::{
        body::Body,
        http::{header, Request, Response, StatusCode},
        Router,
    };
    use std::collections::HashSet;
    use tower::ServiceExt;
    use tower_cookies::cookie;
    use tower_sessions::SessionManagerLayer;
    use tower_sessions_sqlx_store::{sqlx::SqlitePool, SqliteStore};

    use crate::middleware_builder::{
        MissingAuthHandlerParams, Predicate, Require, RequireBuilder, Rstr,
    };
    use crate::{AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend};

    macro_rules! auth_layer {
        () => {{
            let pool = SqlitePool::connect(":memory:").await.unwrap();
            let session_store = SqliteStore::new(pool.clone());
            session_store.migrate().await.unwrap();

            let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

            AuthManagerLayerBuilder::new(Backend, session_layer).build()
        }};
    }

    #[derive(Clone)]
    struct TestState {
        req_perm: Vec<Permission>,
    }

    //TODO: technically needs only refs
    async fn verify_permissions(backend: Backend, user: User, state: TestState) -> bool {
        let req_perms = &state.req_perm;
        let Ok(u_perms) = backend.get_user_permissions(&user).await else {
            return false;
        };

        println!("required: {:?}", req_perms);
        println!("user: {:?}", u_perms);
        let allow = req_perms.iter().any(|perm| u_perms.contains(perm));
        println!("allow: {}", allow);
        allow
    }

    #[derive(Debug, Clone)]
    struct User;

    impl AuthUser for User {
        type Id = i64;

        fn id(&self) -> Self::Id {
            0
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Debug, Clone)]
    struct Credentials;

    #[derive(thiserror::Error, Debug)]
    struct Error;

    impl std::fmt::Display for Error {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Backend;

    impl AuthnBackend for Backend {
        type User = User;
        type Credentials = Credentials;
        type Error = Error;

        async fn authenticate(
            &self,
            _: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }

        async fn get_user(
            &self,
            _: &<<Backend as AuthnBackend>::User as AuthUser>::Id,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct Permission {
        pub name: String,
    }

    impl From<&str> for Permission {
        fn from(name: &str) -> Self {
            Permission {
                name: name.to_string(),
            }
        }
    }

    impl AuthzBackend for Backend {
        type Permission = Permission;

        async fn get_user_permissions(
            &self,
            _user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            let perms: HashSet<Self::Permission> =
                HashSet::from_iter(["test.read".into(), "test.write".into()]);
            Ok(perms)
        }
    }
    fn get_session_cookie(res: &Response<Body>) -> Option<String> {
        res.headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .and_then(|cookie_str| {
                let cookie = cookie::Cookie::parse(cookie_str);
                cookie.map(|c| c.to_string()).ok()
            })
    }

    // Classic Tests (no state)
    #[tokio::test]
    async fn test_login_required() {
        let require_login: Require<Backend> = RequireBuilder::new().state(()).build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = Request::builder()
            .uri("/")
            .header(header::COOKIE, session_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // #[tokio::test]
    // async fn test_login_required_with_login_url() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(Backend, login_url = "/login"))
    //         .route(
    //             "/login",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2F")
    //     );
    //
    //     let req = Request::builder()
    //         .uri("/login")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_login_required_with_login_url_and_redirect_field() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(
    //             Backend,
    //             login_url = "/signin",
    //             redirect_field = "next_uri"
    //         ))
    //         .route(
    //             "/signin",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/signin?next_uri=%2F")
    //     );
    //
    //     let req = Request::builder()
    //         .uri("/signin")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_permission_required() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(permission_required!(Backend, "test.read"))
    //         .route(
    //             "/login",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::FORBIDDEN);
    //
    //     let req = Request::builder()
    //         .uri("/login")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_permission_required_multiple_permissions() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(permission_required!(Backend, "test.read", "test.write"))
    //         .route(
    //             "/login",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::FORBIDDEN);
    //
    //     let req = Request::builder()
    //         .uri("/login")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_permission_required_with_login_url() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(permission_required!(
    //             Backend,
    //             login_url = "/login",
    //             "test.read"
    //         ))
    //         .route(
    //             "/login",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2F")
    //     );
    //
    //     let req = Request::builder()
    //         .uri("/login")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_permission_required_with_login_url_and_redirect_field() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(permission_required!(
    //             Backend,
    //             login_url = "/signin",
    //             redirect_field = "next_uri",
    //             "test.read"
    //         ))
    //         .route(
    //             "/signin",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/signin?next_uri=%2F")
    //     );
    //
    //     let req = Request::builder()
    //         .uri("/signin")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_permission_required_missing_permissions() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(permission_required!(
    //             Backend,
    //             "test.read",
    //             "test.write",
    //             "admin.read"
    //         ))
    //         .route(
    //             "/login",
    //             axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
    //                 auth_session.login(&User).await.unwrap();
    //             }),
    //         )
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::FORBIDDEN);
    //
    //     let req = Request::builder()
    //         .uri("/login")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     let session_cookie =
    //         get_session_cookie(&res).expect("Response should have a valid session cookie");
    //
    //     let req = Request::builder()
    //         .uri("/")
    //         .header(header::COOKIE, session_cookie)
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::FORBIDDEN);
    // }
    //
    // #[tokio::test]
    // async fn test_redirect_uri_query() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(Backend, login_url = "/login"))
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder()
    //         .uri("/?foo=bar&foo=baz")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2F%3Ffoo%3Dbar%26foo%3Dbaz")
    //     );
    // }
    //
    // #[tokio::test]
    // async fn test_login_url_query() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(
    //             Backend,
    //             login_url = "/login?foo=bar&foo=baz"
    //         ))
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.clone().oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2F&foo=bar&foo=baz")
    //     );
    //
    //     let req = Request::builder()
    //         .uri("/?a=b&a=c")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2F%3Fa%3Db%26a%3Dc&foo=bar&foo=baz")
    //     );
    // }
    //
    // #[tokio::test]
    // async fn test_login_url_explicit_redirect() {
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(
    //             Backend,
    //             login_url = "/login?next_url=%2Fdashboard",
    //             redirect_field = "next_url"
    //         ))
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next_url=%2Fdashboard")
    //     );
    //
    //     let app = Router::new()
    //         .route("/", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(
    //             Backend,
    //             login_url = "/login?next=%2Fdashboard"
    //         ))
    //         .layer(auth_layer!());
    //
    //     let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2Fdashboard")
    //     );
    // }
    //
    // #[tokio::test]
    // async fn test_nested() {
    //     let nested = Router::new()
    //         .route("/foo", axum::routing::get(|| async {}))
    //         .route_layer(login_required!(Backend, login_url = "/login"));
    //     let app = Router::new().nest("/nested", nested).layer(auth_layer!());
    //
    //     let req = Request::builder()
    //         .uri("/nested/foo")
    //         .body(Body::empty())
    //         .unwrap();
    //     let res = app.oneshot(req).await.unwrap();
    //     assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    //     assert_eq!(
    //         res.headers()
    //             .get(header::LOCATION)
    //             .and_then(|h| h.to_str().ok()),
    //         Some("/login?next=%2Fnested%2Ffoo")
    //     );
    // }

    //New test (with state)

    // #[test]
    // fn test_require_builder_type_definitions() {
    //     let state = TestState {
    //         req_perm: vec!["test.read".into()],
    //     };
    //
    //     let _fully_qualified: Require<Backend, TestState, Body> = RequireBuilder::new()
    //         .login_url("/login")
    //         .redirect_field("next")
    //         .predicate(|backend, user, state| verify_permissions(backend, user, state))
    //         .state(state.clone())
    //         .on_restricted(|_| async { StatusCode::UNAUTHORIZED.into_response() })
    //         .build();
    //
    //     let _: Require<Backend> = RequireBuilder::new()
    //         .login_url("/login")
    //         .redirect_field("next")
    //         .state(())
    //         .on_restricted(|_| async { StatusCode::UNAUTHORIZED.into_response() })
    //         .build();
    //
    //     let _: Require<Backend> = RequireBuilder::new()
    //         .state(())
    //         .on_restricted(|_| async { StatusCode::UNAUTHORIZED.into_response() })
    //         .build();
    //
    //     let _: Require<Backend> = RequireBuilder::new()
    //         .state(())
    //         .on_restricted(|_| async { StatusCode::UNAUTHORIZED.into_response() })
    //         .build();
    //
    //     let _: Require<Backend> = RequireBuilder::new()
    //         .state(())
    //         .on_restricted(|_| async { StatusCode::UNAUTHORIZED.into_response() })
    //         .build();
    //
    //     // TODO: add no state
    //     // let _: RequireFull<Backend> = RequireBuilder::new()
    //     //     .build();
    //
    //     assert!(true)
    // }

    #[tokio::test]
    async fn test_login_required_perm_with_state() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let f = |backend, user, state| verify_permissions(backend, user, state);
        let require_login: Require<Backend, TestState, Body> = RequireBuilder::new()
            .fallback(MissingAuthHandlerParams::Params {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .predicate(Predicate::from_closure(f))
            .state(state.clone())
            .on_restrict(Rstr::from_closure(|_| async {
                StatusCode::UNAUTHORIZED.into_response()
            }))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .with_state(state)
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

        let req = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = Request::builder()
            .uri("/")
            .header(header::COOKIE, session_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_url_explicit_redirect_with_permissions() {
        let state = TestState {
            req_perm: vec!["test.read".into(), "test.write".into()],
        };

        let require_login: Require<Backend, TestState, Body> = RequireBuilder::new()
            .fallback(MissingAuthHandlerParams::Params {
                redirect_field: Some("next_url".to_string()),
                login_url: Some("/login?next_url=%2Fdashboard".to_string()),
            })
            // .fallback(MissingAuthHandlerParams::from_handler(|_, _| async {
            //     StatusCode::UNAUTHORIZED.into_response()
            // }))
            .predicate(Predicate::from_closure(|backend, user, state| {
                verify_permissions(backend, user, state)
            }))
            .state(state.clone())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/signin",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next_url=%2Fdashboard")
        );

        //
        let req = Request::builder()
            .uri("/signin")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = Request::builder()
            .uri("/")
            .header(header::COOKIE, session_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}

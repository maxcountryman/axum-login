use crate::{url_with_redirect_query, AuthSession, AuthnBackend, AuthzBackend};
use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::{StatusCode};
use axum::response::Response;
use std::fmt;
use std::fmt::Debug;
use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_LOGIN_URL: &str = "/signin";
const DEFAULT_REDIRECT_FIELD: &str = "next";
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
//TODO: there is a mess with how to name different handlers and their wrappers
//TODO: use own futures
//TODO: The current implementation of Handlers is subject to change
type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
type RestrictFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;
type FallbackFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;

/// A Tower service that enforces authentication and authorization requirements.
///
/// This service checks for authentication, if it fails, it responds with fallback  applies a
/// predicate function to determine if
/// the request should
/// be
/// allowed to proceed. If the predicate fails, it applies either a restriction response or a fallback response.
pub struct RequireService<S, B: AuthnBackend, ST: Clone, T> {
    inner: S,
    /// Function used to check user permissions or other requirements
    predicate: PredicateStateFn<B, ST>,
    /// Handler used in case the user fails authentication
    fallback: FallbackFn<T>,
    /// State of the application
    state: ST,
    /// Handler used in case the user fails predicate check
    restrict: RestrictFn<T>,
}

impl<S, B, ST, T> fmt::Debug for RequireService<S, B, ST, T>
where
    S: fmt::Debug,
    B: AuthnBackend,
    ST: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireService")
            .field("inner", &self.inner)
            .field("predicate", &"<function>")
            .field("fallback", &"<function>")
            .field("state", &self.state)
            .field("restrict", &"<function>")
            .finish()
    }
}

//umm, manual clone, yes
impl<S, B, ST, T> Clone for RequireService<S, B, ST, T>
where
    S: Clone,
    ST: Clone,
    B: AuthnBackend,
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
    B: AuthnBackend + Clone + Send + 'static,
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
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();

        let predicate = Arc::clone(&self.predicate);
        let fallback = Arc::clone(&self.fallback);
        let restrict = Arc::clone(&self.restrict);
        let state = self.state.clone();

        // This should help
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            match auth_session {
                Some(AuthSession {
                    user: Some(user),
                    backend,
                    ..
                }) => {
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
                Some(_auth_session) => {
                    // No user in session, use fallback
                    let response = fallback(req).await;
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
    B: Clone + AuthnBackend,
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
    B: Clone + AuthnBackend,
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

/// A builder for creating [`Require`] layers with authentication and authorization requirements.
///
/// This builder provides a fluent interface for configuring how requests should be handled
/// when they don't meet the specified authentication or authorization requirements.
///
/// # Type Parameters
///
/// * `B` - The authentication backend type that implements [`AuthnBackend`]
/// * `ST` - The state type passed to the predicate function (defaults to `()`)
/// * `T` - The request body type (defaults to [`Body`])
///
/// # Examples
///
/// ```rust
/// use axum_login::{RequireBuilder, Predicate, Fallback};
///
/// let require_layer = RequireBuilder::new()
///     .predicate(Predicate::from_closure(|backend, user, state| async move {
///         // Custom authorization logic here
///         true
///     }))
///     .fallback(Fallback::Params {
///         login_url: Some("/login".to_string()),
///         redirect_field: Some("next".to_string()),
///     })
///     .build();
/// ```
pub struct RequireBuilder<B: AuthnBackend, ST = (), T = Body> {
    /// Function for checking user permissions
    predicate: Option<PredicateStateFn<B, ST>>,
    /// Handler for user lacking permissions
    restrict: Option<RestrictFn<T>>,
    /// Handler for user authentication
    fallback: Option<FallbackFn<T>>,
    /// State to get values dynamically
    state: Option<ST>,
}

/// Represents different types of predicates for authorization checks.
/// A predicate determines whether a user should be allowed access to a protected resource.
/// It can be either a custom function or a parameter-based check for specific permissions.
///
/// # Type Parameters
/// * `B` - The authorization backend type that implements [`AuthzBackend`]
/// * `ST` - The state type passed to the predicate function
#[derive(Clone)]
pub enum Predicate<B: AuthzBackend, ST> {
    /// A custom function that performs authorization logic.
    /// The function receives the backend, user, and state and returns whether
    /// the user should be authorized.
    Function(PredicateStateFn<B, ST>),

    /// Parameter-based authorization that checks for specific permissions.
    /// This variant automatically checks if the user has ALL the specified permissions.
    Params {
        /// The permissions required for access
        permissions: Vec<B::Permission>,
    },
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
    /// Creates a predicate from a closure.
    /// # Parameters
    ///
    /// * `f` - A closure that takes the backend, user, and state, returning a future that resolves to a boolean
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_login::Predicate;
    ///
    /// let predicate = Predicate::from_closure(|backend, user, state| async move {
    ///     backend.has_perm(&user, "read".into()).await.unwrap_or(false)
    /// });
    /// ```
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
    B::Permission: Clone + Debug,
    ST: Clone + Send + Sync + 'static,
{
    fn from(params: Predicate<B, ST>) -> Self {
        match params {
            Predicate::Function(f) => Arc::new(move |backend, user, state| {
                Box::pin(f(backend, user, state)) as Pin<Box<dyn Future<Output = bool> + Send>>
            }),

            Predicate::Params {
                permissions: req_perms,
                ..
            } => {
                //TODO: redundant
                let req_perms = req_perms.clone();
                Arc::new(move |backend: B, user: B::User, _state: ST| {
                    let req_perms = req_perms.clone();
                    Box::pin(async move {
                        let Ok(u_perms) = backend.get_user_permissions(&user).await else {
                            return false;
                        };
                        let allow = req_perms.iter().all(|perm| u_perms.contains(perm));
                        allow
                    })
                })
            }
        }
    }
}

/// Represents different ways to specify a permission-restricted handler.
///
/// When a request fails authorization, but the user is authenticated, a restriction
/// response is used instead of redirecting to login page.
pub enum Rstr<T = Body> {
    /// A custom function that generates the restriction response.
    Function(RestrictFn<T>),

    /// Parameter-based restriction configuration.
    Params {
        i_dunno: Option<String>, //TODO: haven't decidede yet
    },
}
impl<T> fmt::Debug for Rstr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rstr::Function(_) => f.debug_tuple("HandlerFunc").field(&"<closure>").finish(),
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
            Rstr::Function(f) => Arc::new(move |req| {
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
    /// Creates a restriction handler from a closure.
    ///
    /// # Parameters
    ///
    /// * `f` - A closure that takes a request and returns a future that resolves to a response
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_login::Rstr;
    /// use axum::http::{Response, StatusCode};
    ///
    /// let restriction = Rstr::from_closure(|_req| async {
    ///     Response::builder()
    ///         .status(StatusCode::FORBIDDEN)
    ///         .body("Access denied".into())
    ///         .unwrap()
    /// });
    /// ```
    pub fn from_closure<F, Fut>(f: F) -> Self
    where
        F: Fn(Request<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self::Function(Arc::new(move |req| Box::pin(f(req))))
    }
}

/// Represents different ways to specify a fallback handler.
///
/// When a request requires authentication but the user is not authenticated,
/// a fallback response is used.
#[derive(Clone)]
pub enum Fallback<T = Body> {
    /// A custom function that generates the fallback response.
    Function(FallbackFn<T>),

    /// Parameter-based fallback configuration for redirect-style authentication.
    Params {
        /// The field name used for the redirect URL in the query string
        redirect_field: Option<String>,
        /// The URL to redirect to for authentication
        login_url: Option<String>,
    },
}

impl<T> fmt::Debug for Fallback<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fallback::Function(_) => f.debug_tuple("HandlerFunc").field(&"<closure>").finish(),
            Fallback::Params {
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

impl<T> Fallback<T>
where
    T: Send + 'static,
{
    /// Creates a fallback handler from a closure.
    pub fn from_handler<F, Fut>(f: F) -> Self
    where
        F: Fn(Request<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Fallback::Function(Arc::new(move |req| Box::pin(f(req))))
    }
}

impl<T> From<Fallback<T>> for FallbackFn<T>
where
    T: Send + 'static,
{
    fn from(params: Fallback<T>) -> Self {
        match params {
            Fallback::Function(f) => Arc::new(move |req| {
                Box::pin(f(req)) as Pin<Box<dyn Future<Output = Response> + Send>>
            }),

            Fallback::Params {
                redirect_field,
                login_url,
                ..
            } =>  {
                //TODO: redundant
                let login_url = login_url.unwrap_or(DEFAULT_LOGIN_URL.to_string());
                let redirect_field = redirect_field.unwrap_or(DEFAULT_REDIRECT_FIELD.to_string());

                Arc::new(move |req| {
                    let login_url = login_url.clone();
                    let redirect_field = redirect_field.clone();

                    Box::pin(async move {
                        let original_uri = req.extensions().get::<OriginalUri>().cloned();
                        match original_uri {
                            None => Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body("Internal Server Error".into())
                                .unwrap(),
                            Some(OriginalUri(original_uri)) => {
                                let url = url_with_redirect_query(
                                    &login_url,
                                    &redirect_field,
                                    original_uri,
                                )
                                .unwrap();
                                Response::builder()
                                    .status(StatusCode::TEMPORARY_REDIRECT)
                                    .header("Location", url.to_string())
                                    .body("Redirecting...".into())
                                    .unwrap()
                            }
                        }
                    }) as Pin<Box<dyn Future<Output = Response> + Send>>
                })
            }
        }
    }
}

impl<B: AuthnBackend, ST: Clone, T: 'static + Send> RequireBuilder<B, ST, T> {
    /// Creates a new `RequireBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            predicate: None,
            restrict: None,
            fallback: None,
            state: None,
        }
    }

    /// Sets the custom predicate function for authorization checks.
    /// The predicate determines whether a request should be allowed to proceed.
    ///
    /// # Examples
    /// ```rust
    /// use axum_login::{RequireBuilder, Predicate};
    ///
    /// let builder = RequireBuilder::new()
    ///     .predicate(Predicate::from_closure(|backend, user, state| async move {
    ///         true
    ///     }));
    /// ```
    pub fn predicate(mut self, pred: Predicate<B, ST>) -> RequireBuilder<B, ST, T>
    where
        B: AuthnBackend + AuthzBackend + 'static,
        B::User: 'static,
        B::Permission: Clone + Debug,
        ST: Clone + Send + Sync + 'static,
    {
        self.predicate = Some(pred.into());

        self
    }

    /// Sets the fallback response for unauthenticated requests.
    /// When a request requires authentication but the user is not authenticated,
    /// the fallback response is used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum_login::{RequireBuilder, Fallback};
    ///
    /// let builder = RequireBuilder::new()
    ///     .fallback(Fallback::Params {
    ///         login_url: Some("/signin".to_string()),
    ///         redirect_field: Some("next".to_string()),
    ///     });
    /// ```
    pub fn fallback(mut self, func: Fallback<T>) -> Self {
        self.fallback = Some(func.into());
        self
    }

    /// Sets the restriction response for unauthorized requests.
    /// When a request fails authorization but the user is authenticated,
    /// the restriction response is used instead of redirecting.
    /// # Examples
    ///
    /// ```rust
    /// use axum_login::{RequireBuilder, Rstr};
    /// use axum::http::StatusCode;
    ///
    /// let builder = RequireBuilder::new()
    ///     .on_restrict(Rstr::from_closure(|_req| async {
    ///         StatusCode::FORBIDDEN.into_response()
    ///     }));
    /// ```
    pub fn on_restrict(mut self, func: Rstr<T>) -> Self
    where
        T: Send + 'static,
    {
        self.restrict = Some(func.into());
        self
    }

    /// Sets the state value passed to the predicate function.
    /// # Examples
    ///
    /// ```rust
    /// use axum_login::RequireBuilder;
    ///
    /// #[derive(Clone)]
    /// struct MyState {
    ///     required_role: String,
    /// }
    ///
    /// let state = MyState {
    ///     required_role: "admin".to_string(),
    /// };
    ///
    /// let builder = RequireBuilder::new().state(state);
    /// ```
    pub fn state(mut self, state: ST) -> Self {
        self.state = Some(state);
        self
    }
    fn default_fallback() -> FallbackFn<T> {
        Arc::new(|_req| {
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

    /// Build the resulting middleware
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

    use crate::middleware_builder::{Fallback, Predicate, Require, RequireBuilder, Rstr};
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

        let allow = req_perms.iter().any(|perm| u_perms.contains(perm));
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

    #[tokio::test]
    async fn test_login_required_with_login_url() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .state(())
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
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
            Some("/login?next=%2F")
        );

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
    async fn test_login_required_with_login_url_and_redirect_field() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: Some("next_uri".to_string()),
                login_url: Some("/signin".to_string()),
            })
            // .predicate(Predicate::Params {
            //     permissions: permissions.iter().map(|&p| p.into()).collect(),
            // })
            .state(())
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
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
            Some("/signin?next_uri=%2F")
        );

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

    #[tokio::test]
    async fn test_permission_required() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require: Require<Backend> = RequireBuilder::new()
            // .fallback(Fallback::Params {
            //     redirect_field: Some("next_uri".to_string()),
            //     login_url: Some("/signin".to_string()),
            // })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();

        //WARN: This differs from macros implementation. Macros returned FORBIDDEN
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

    #[tokio::test]
    async fn test_permission_required_multiple_permissions() {
        let permissions: Vec<&str> = vec!["test.read", "test.write"];
        let require: Require<Backend> = RequireBuilder::new()
            // .fallback(Fallback::Params {
            //     redirect_field: Some("next_uri".to_string()),
            //     login_url: Some("/signin".to_string()),
            // })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();

        //WARN: This differs from macros implementation. Macros returned FORBIDDEN
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

    #[tokio::test]
    async fn test_permission_required_with_login_url() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
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
            Some("/login?next=%2F")
        );

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
    async fn test_permission_required_with_login_url_and_redirect_field() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: Some("next_uri".to_string()),
                login_url: Some("/signin".to_string()),
            })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
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
            Some("/signin?next_uri=%2F")
        );

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

    #[tokio::test]
    async fn test_permission_required_missing_permissions() {
        let permissions: Vec<&str> = vec!["test.read", "test.write", "admin.read"];
        let require: Require<Backend> = RequireBuilder::new()
            // .fallback(Fallback::Params {
            //     redirect_field: None,
            //     login_url: Some("/login".to_string()),
            // })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        //WARN: This differs from macros implementation. Macros returned FORBIDDEN
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
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_redirect_uri_query() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .state(())
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .layer(auth_layer!());

        let req = Request::builder()
            .uri("/?foo=bar&foo=baz")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next=%2F%3Ffoo%3Dbar%26foo%3Dbaz")
        );
    }

    #[tokio::test]
    async fn test_login_url_query() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login?foo=bar&foo=baz".to_string()),
            })
            .state(())
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next=%2F&foo=bar&foo=baz")
        );

        let req = Request::builder()
            .uri("/?a=b&a=c")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next=%2F%3Fa%3Db%26a%3Dc&foo=bar&foo=baz")
        );
    }

    #[tokio::test]
    async fn test_login_url_explicit_redirect() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: Some("next_url".to_string()),
                login_url: Some("/login?next_url=%2Fdashboard".to_string()),
            })
            .state(())
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next_url=%2Fdashboard")
        );

        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login?next=%2Fdashboard".to_string()),
            })
            .state(())
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next=%2Fdashboard")
        );
    }

    #[tokio::test]
    async fn test_nested() {
        let require: Require<Backend> = RequireBuilder::new()
            .fallback(Fallback::Params {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .state(())
            .build();
        let nested = Router::new()
            .route("/foo", axum::routing::get(|| async {}))
            .route_layer(require);
        let app = Router::new().nest("/nested", nested).layer(auth_layer!());

        let req = Request::builder()
            .uri("/nested/foo")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok()),
            Some("/login?next=%2Fnested%2Ffoo")
        );
    }

    //New test (with state)

    #[tokio::test]
    async fn test_require_builder_all_combinations() {
        //TODO: add tests with state
        #[derive(Clone)]
        struct TestState {
            req_perm: Vec<String>,
        }

        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        // Predicate factory functions
        let predicate_factories: Vec<Box<dyn Fn() -> Predicate<Backend, TestState>>> = vec![
            Box::new(|| {
                Predicate::from_closure(|_b: Backend, _u: User, _s: TestState| async { true })
            }),
            Box::new(|| Predicate::Params {
                permissions: vec!["test.read".into()],
            }),
        ];

        // Fallback factory functions
        let fallback_factories: Vec<Box<dyn Fn() -> Fallback>> = vec![
            Box::new(|| Fallback::Params {
                redirect_field: Some("redirect".to_string()),
                login_url: Some("/login".to_string()),
            }),
            Box::new(|| {
                Fallback::from_handler(|_req| async {
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body("Unauthorized".into())
                        .unwrap()
                })
            }),
        ];

        // Restrict factory functions
        let restrict_factories: Vec<Box<dyn Fn() -> Rstr<Body>>> = vec![
            Box::new(|| {
                Rstr::from_closure(|_req| async {
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body("Forbidden".into())
                        .unwrap()
                })
            }),
            Box::new(|| Rstr::Params {
                i_dunno: Some("param".to_string()),
            }),
        ];

        for pred_factory in predicate_factories {
            for fallback_factory in &fallback_factories {
                for restrict_factory in &restrict_factories {
                    // Create fresh instances
                    let pred = pred_factory();
                    let fallback = fallback_factory();
                    let restrict = restrict_factory();

                    // Build
                    let require: Require<Backend, TestState, Body> = RequireBuilder::new()
                        .predicate(pred)
                        .fallback(fallback)
                        .on_restrict(restrict)
                        .state(state.clone())
                        .build();

                    // Test fallback handler response
                    let req = axum::http::Request::builder()
                        .uri("/")
                        .body(Body::empty())
                        .unwrap();

                    let fallback_resp = (require.fallback)(req).await;
                    assert!(matches!(
                        fallback_resp.status(),
                        StatusCode::UNAUTHORIZED | StatusCode::TEMPORARY_REDIRECT | StatusCode::INTERNAL_SERVER_ERROR
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn test_login_required_perm_with_state() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let f = |backend, user, state| verify_permissions(backend, user, state);
        let require_login: Require<Backend, TestState, Body> = RequireBuilder::new()
            .fallback(Fallback::Params {
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
            .fallback(Fallback::Params {
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

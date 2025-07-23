use crate::{AuthSession, AuthnBackend, AuthzBackend};
use axum::extract::{OriginalUri, Request};
use axum::http::StatusCode;
use axum::response::Response;
use axum::response::{IntoResponse, Redirect};
use std::future::{ready, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use axum::body::Body;
use tower_layer::Layer;
use tower_service::Service;

// TODO: I am not sure if the current type implementation of these functions is great.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
pub type FallbackFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;

pub struct RequireService<S, B: AuthnBackend, ST: Clone, T> {
    inner: S,
    /// Function used to check user permissions or other requirements
    predicate: PredicateStateFn<B, ST>,
    /// Handler used in case the user fails predicate check
    fallback: FallbackFn<T>,
    /// State of the application
    state: ST,
    /// Field used to redirect unauthorized user
    redirect_field: Option<String>,
    /// Login url used to redirect unauthorized user
    login_url: Option<String>,
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
            redirect_field: self.redirect_field.clone(),
            login_url: self.login_url.clone(),
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

        //Later
        let fallback = self.fallback.clone();
        let predicate = self.predicate.clone();
        let state = self.state.clone();
        let mut inner = self.inner.clone(); // TODO: Cloning this is bad
        let redirect_field = self
            .redirect_field
            .as_deref()
            .unwrap_or("next_uri")
            .to_string();
        let login_url = self.login_url.as_deref().unwrap_or("/signin").to_string();

        Box::pin(async move {
            match (original_uri, auth_session) {
                (
                    Some(_), // TODO: remove
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
                        // Unauthorized
                        let response = fallback(req).await;
                        Ok(response)
                    }
                }
                (Some(original_uri), Some(_auth_session)) => {
                    // No user in session, redirect to login
                    match crate::url_with_redirect_query(
                        &login_url,
                        &redirect_field,
                        original_uri.0,
                    ) {
                        Ok(login_url) => {
                            // TODO: separate handler for redirects mayybe
                            // req.extensions_mut().insert(login_url);
                            // let response = (fallback)(req).await;
                            let response =
                                Redirect::temporary(&login_url.to_string()).into_response();

                            Ok(response)
                        }
                        Err(_) => Ok(axum::response::IntoResponse::into_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                        )),
                    }
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
    pub fallback: FallbackFn<T>,
    pub state: ST,
    pub redirect_field: Option<String>,
    pub login_url: Option<String>,
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
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            redirect_field: self.redirect_field.clone(),
            login_url: self.login_url.clone(),
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
            redirect_field: self.redirect_field.clone(),
            login_url: self.login_url.clone(),
        }
    }
}

// --- The Builder

//TODO: create Require without state (nullable state)
pub struct RequireBuilder<B: AuthnBackend, ST = (), T = ()> {
    predicate: Option<PredicateStateFn<B, ST>>,
    fallback: Option<FallbackFn<T>>,
    login_url: Option<String>,
    redirect_field: Option<String>,
    state: Option<ST>,
}

impl<B: AuthnBackend, ST: Clone, T> RequireBuilder<B, ST, T> {
    pub fn new() -> Self {
        Self {
            predicate: None,
            fallback: None,
            login_url: None,
            redirect_field: None,
            state: None,
        }
    }
    /// Always returns Forbidden
    fn default_fallback() -> FallbackFn<T> {
        Arc::new(|_| {
            Box::pin(async {
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body("Forbidden".into())
                    .unwrap()
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }

    /// Always returns True
    fn default_predicate() -> PredicateStateFn<B, ST> {
        Arc::new(|_backend: B, _user: B::User, _state: ST| {
            Box::pin(ready(true)) as Pin<Box<dyn Future<Output = bool> + Send>>
        })
    }

    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }
    pub fn state(mut self, state: ST) -> Self {
        self.state = Some(state);
        self
    }

    pub fn redirect_field(mut self, field: impl Into<String>) -> Self {
        self.redirect_field = Some(field.into());
        self
    }

    pub fn predicate<F, Fut>(mut self, pred: F) -> RequireBuilder<B, ST, T>
    where
        F: Fn(B, B::User, ST) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        // Umm, I very not sure if I am doing this right
        let predicate_fn = Arc::new(move |backend, user, state| {
            Box::pin(pred(backend, user, state)) as Pin<Box<dyn Future<Output = bool> + Send>>
        });
        self.predicate = Some(predicate_fn);
        self
    }

    pub fn on_failure<F, Fut>(mut self, fail: F) -> RequireBuilder<B, ST, T>
    where
        F: Fn(Request<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        let fallback_fn = Arc::new(move |req| {
            Box::pin(fail(req)) as Pin<Box<dyn Future<Output = Response> + Send>>
        });
        self.fallback = Some(fallback_fn);
        self
    }
    pub fn build(self) -> Require<B, ST, T> {
        Require {
            predicate: self.predicate.unwrap_or_else(Self::default_predicate),
            fallback: self.fallback.unwrap_or_else(Self::default_fallback),
            state: self
                .state
                .expect("You must provide state with `.state(...)`"),
            redirect_field: self.redirect_field,
            login_url: self.login_url,
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

    use crate::middleware_builder::{RequireBuilder, Require};
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


    #[test]
    fn test_require_builder_type_definitions() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let _fully_qualified: Require<Backend, TestState, Body> = RequireBuilder::new()
            .login_url("/login")
            .redirect_field("next")
            .predicate(|backend, user, state| verify_permissions(backend, user, state))
            .state(state.clone())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .build();

        let _: Require<Backend> = RequireBuilder::new()
            .login_url("/login")
            .redirect_field("next")
            .state(())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .build();

        let _: Require<Backend> = RequireBuilder::new()
            .state(())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .build();

        let _: Require<Backend> = RequireBuilder::new()
            .state(())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .build();

        let _: Require<Backend> = RequireBuilder::new()
            .state(())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .build();

        // TODO: add no state
        // let _: RequireFull<Backend> = RequireBuilder::new()
        //     .build();

        assert!(true)
    }


    //TODO: Add much more tests
    #[tokio::test]
    async fn test_login_required() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let require_login: Require<Backend, TestState, Body> = RequireBuilder::new()
            .login_url("/login")
            .redirect_field("next")
            .predicate(|backend, user, state| verify_permissions(backend, user, state))
            .state(state.clone())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
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
            .login_url("/login?next_url=%2Fdashboard")
            .redirect_field("next_url")
            .predicate(|backend, user, state| verify_permissions(backend, user, state))
            .state(state.clone())
            .on_failure(|_| async { StatusCode::UNAUTHORIZED.into_response() })
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

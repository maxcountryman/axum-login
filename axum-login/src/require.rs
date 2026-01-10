//! Authentication requirement middleware for Axum.
//!
//! This module provides the [`Require`] type, which acts as a configurable
//! middleware layer for enforcing authentication and access control in Axum
//! applications. It uses a customizable predicate with configurable restrict
//! and fallback handlers to control access to routes based on authentication.
//! ## Overview
//!
//! ```rust,no_run
//! # use std::collections::HashMap;
//! #
//! # use axum_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone, Default)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use axum::{
//!     routing::{get, post},
//!     Router,
//! };
//! use axum_login::{
//!     require::{RedirectFallback, Require, SimplePredicate},
//!     tower_sessions::{MemoryStore, SessionManagerLayer},
//!     AuthManagerLayerBuilder,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Session layer.
//!     let session_store = MemoryStore::default();
//!     let session_layer = SessionManagerLayer::new(session_store);
//!
//!     // Auth service.
//!     let backend = Backend::default();
//!     let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
//!
//!     // Permission control layer
//!     let require = Require::<Backend>::builder()
//!         .fallback(RedirectFallback::new().login_url("/login"))
//!         .build();
//!
//!     let app = Router::new()
//!         .route("/protected", get::<(), _, _>(todo!()))
//!         .route_layer(require)
//!         .route("/login", post::<(), _, _>(todo!()))
//!         .route("/login", get::<(), _, _>(todo!()))
//!         .layer(auth_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app.into_make_service()).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Common patterns
//!
//! Require a permission and redirect unauthenticated users to `/login`:
//!
//! ```rust,no_run
//! use axum_login::require::{RedirectFallback, Require, SimplePredicate};
//! use axum_login::{AuthUser, AuthnBackend, AuthzBackend, UserId};
//!
//! #[derive(Clone, Debug)]
//! struct User;
//!
//! impl AuthUser for User {
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         0
//!     }
//!
//!     fn session_auth_hash(&self) -> &[u8] {
//!         &[]
//!     }
//! }
//!
//! #[derive(Clone, Debug, Eq, PartialEq, Hash)]
//! struct Permission(&'static str);
//!
//! #[derive(Clone)]
//! struct Backend;
//!
//! impl AuthnBackend for Backend {
//!     type User = User;
//!     type Credentials = ();
//!     type Error = std::convert::Infallible;
//!
//!     async fn authenticate(
//!         &self,
//!         _: Self::Credentials,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//!
//!     async fn get_user(
//!         &self,
//!         _: &UserId<Self>,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//! }
//!
//! impl AuthzBackend for Backend {
//!     type Permission = Permission;
//! }
//!
//! let predicate = SimplePredicate::<Backend>::new()
//!     .with_permissions([Permission("admin.read")]);
//!
//! let require = Require::<Backend>::builder()
//!     .predicate(predicate)
//!     .fallback(RedirectFallback::new().login_url("/login"))
//!     .build();
//! ```
mod builder;
mod handler;
mod predicate;
mod service;


use std::{future::Future, marker::PhantomData, pin::Pin};

use axum::body::Body;
use tower_layer::Layer;

pub use self::{
    builder::RequireBuilder,
    handler::{
        AsyncFallbackHandler, DefaultFallback, DefaultRestrict, RedirectFallback,
        SimpleResponseFallback,
    },
    predicate::{AsyncPredicate, CheckMode, DefaultPredicate, SimplePredicate},
    service::RequireService,
};
use crate::AuthnBackend;

/// A Future in a Box
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A type alias for the default [`Require`] configuration.
pub type RequireLayer<B, ST = (), T = Body> = Require<B, ST, T>;

/// A type alias for the default [`RequireBuilder`] configuration.
pub type RequireBuilderLayer<B, ST = (), T = Body> = RequireBuilder<B, ST, T>;

/// A configurable authentication and access control layer.
///
/// The [`Require`] struct serves as the core component of the authentication
/// middleware. It determines whether a request satisfies an access predicate
/// and applies restriction or fallback logic when access is denied.
///
/// This type is typically constructed using the [`Require::builder`] or
/// [`Require::builder_with_state`] methods.
///
/// # Type Parameters
/// - `B`: The authentication backend implementing [`AuthnBackend`].
/// - `ST`: Shared state used by predicates or handlers.
/// - `T`: Request body type (defaults to [`Body`]).
/// - `Fb`: Fallback handler type (defaults to [`DefaultFallback`]).
/// - `Rs`: Restriction handler type (defaults to [`DefaultRestrict`]).
/// - `Pr`: Predicate type used to determine access (defaults to
///   [`DefaultPredicate`]).
///
/// For most use cases, prefer [`RequireLayer`] and [`RequireBuilderLayer`] to
/// avoid explicit generic parameters.
#[must_use]
#[derive(Debug)]
pub struct Require<
    B,
    ST = (),
    T = Body,
    Fb = DefaultFallback,
    Rs = DefaultRestrict,
    Pr = DefaultPredicate<B, ST>,
> where
    B: AuthnBackend,
{
    /// The predicate that determines if access should be granted.
    pub predicate: Pr,
    /// The restriction response for when the predicate restricts access.
    pub restrict: Rs,
    /// The fallback response for missing authentication.
    pub fallback: Fb,
    /// Arbitrary user state available the predicate.
    pub state: ST,
    /// Internal marker to maintain type safety.
    _phantom: PhantomData<(B, fn() -> T)>,
}

impl<B, Fb, Rs, Pr, ST, T> Require<B, ST, T, Fb, Rs, Pr>
where
    B: AuthnBackend,
{
    /// Creates a new [`Require`] instance with the specified predicate,
    /// restriction, fallback, and state.
    pub fn new(predicate: Pr, restrict: Rs, fallback: Fb, state: ST) -> Self {
        Self {
            predicate,
            restrict,
            fallback,
            state,
            _phantom: PhantomData,
        }
    }
}

// Manual clone, because of Body
impl<B, Fb, Rs, ST, T, Pr> Clone for Require<B, ST, T, Fb, Rs, Pr>
where
    Fb: Clone,
    Rs: Clone,
    Pr: Clone,
    ST: Clone,
    B: AuthnBackend,
{
    fn clone(&self) -> Self {
        Self {
            predicate: self.predicate.clone(),
            restrict: self.restrict.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<B, T> Require<B, (), T>
where
    B: AuthnBackend,
{
    /// Returns a builder for constructing a [`Require`] layer with an empty
    /// state.
    #[inline]
    pub fn builder(
    ) -> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ()>> {
        RequireBuilder::new()
    }
}

impl<B, ST, T> Require<B, ST, T>
where
    B: AuthnBackend,
    DefaultPredicate<B, ST>: AsyncPredicate<B, ST>,
{
    /// Returns a builder for constructing a [`Require`] layer with custom
    /// shared state.
    #[inline]
    pub fn builder_with_state(
        state: ST,
    ) -> RequireBuilder<B, ST, T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ST>> {
        RequireBuilder::new_with_state(state)
    }
}

impl<S, B, ST, T, Fb, Rs, Pr> Layer<S> for Require<B, ST, T, Fb, Rs, Pr>
where
    S: Clone,
    B: Clone + AuthnBackend + Send + Sync + 'static,
    Fb: Clone + Send + Sync + 'static,
    Rs: Clone + Send + Sync + 'static,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + Send + Sync + 'static,
    T: std::marker::Send + 'static,
{
    type Service = RequireService<S, B, ST, T, Fb, Rs, Pr>;

    #[doc(hidden)]
    /// Wraps the given service with the [`Require`] authentication layer.
    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            layer: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use axum::{
        body::Body,
        http::{header, Request, Response, StatusCode},
        response::IntoResponse,
        Router,
    };
    use tower::ServiceExt;
    use tower_cookies::cookie;
    use tower_sessions::SessionManagerLayer;
    use tower_sessions_sqlx_store::{sqlx::SqlitePool, SqliteStore};

    use crate::{
        require::{
            builder::RequireBuilder,
            handler::{RedirectFallback, SimpleResponseFallback},
            predicate::SimplePredicate,
            Require,
        },
        AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend,
    };

    macro_rules! auth_layer {
        () => {{
            let pool = SqlitePool::connect(":memory:").await.unwrap();
            let session_store = SqliteStore::new(pool.clone());
            session_store.migrate().await.unwrap();

            let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

            AuthManagerLayerBuilder::new(TestBackend, session_layer).build()
        }};
    }

    #[derive(Clone)]
    struct TestState {
        req_perm: Vec<TestPermission>,
    }

    async fn verify_permissions(backend: TestBackend, user: User, state: TestState) -> bool {
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
    struct TestBackend;

    impl AuthnBackend for TestBackend {
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
            _: &<<TestBackend as AuthnBackend>::User as AuthUser>::Id,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct TestPermission {
        pub name: String,
    }

    impl From<&str> for TestPermission {
        fn from(name: &str) -> Self {
            TestPermission {
                name: name.to_string(),
            }
        }
    }

    impl AuthzBackend for TestBackend {
        type Permission = TestPermission;

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
        let require_login = RequireBuilder::<TestBackend>::new().build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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

    #[cfg(feature = "macros-middleware")]
    mod parity {
        use axum::routing::get;

        use super::*;
        use crate::{login_required, permission_required};

        async fn request(app: &Router, uri: &str, cookie: Option<&str>) -> Response<Body> {
            let mut req = Request::builder().uri(uri);
            if let Some(cookie) = cookie {
                req = req.header(header::COOKIE, cookie);
            }
            let req = req.body(Body::empty()).unwrap();
            app.clone().oneshot(req).await.unwrap()
        }

        async fn login_cookie(app: &Router) -> String {
            let res = request(app, "/login", None).await;
            get_session_cookie(&res).expect("Response should have a valid session cookie")
        }

        fn location(res: &Response<Body>) -> Option<String> {
            res.headers()
                .get(header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .map(|value| value.to_string())
        }

        #[tokio::test]
        async fn test_login_required_parity_unauthenticated() {
            let builder_layer = RequireBuilder::<TestBackend>::new().build();
            let macro_layer = login_required!(TestBackend);

            let app_builder = Router::new()
                .route("/", get(|| async {}))
                .route_layer(builder_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let app_macro = Router::new()
                .route("/", get(|| async {}))
                .route_layer(macro_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let res_builder = request(&app_builder, "/", None).await;
            let res_macro = request(&app_macro, "/", None).await;

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[tokio::test]
        async fn test_login_required_parity_redirect() {
            let builder_layer = RequireBuilder::<TestBackend>::new()
                .fallback(RedirectFallback::new().login_url("/login"))
                .build();
            let macro_layer = login_required!(TestBackend, login_url = "/login");

            let app_builder = Router::new()
                .route("/", get(|| async {}))
                .route_layer(builder_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let app_macro = Router::new()
                .route("/", get(|| async {}))
                .route_layer(macro_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let res_builder = request(&app_builder, "/?foo=bar", None).await;
            let res_macro = request(&app_macro, "/?foo=bar", None).await;

            assert_eq!(res_builder.status(), res_macro.status());
            assert_eq!(location(&res_builder), location(&res_macro));
        }

        #[tokio::test]
        async fn test_permission_required_parity_unauthenticated() {
            let builder_layer = RequireBuilder::<TestBackend>::new()
                .predicate(SimplePredicate::new().with_permissions(vec!["test.read"]))
                .build();
            let macro_layer = permission_required!(TestBackend, "test.read");

            let app_builder = Router::new()
                .route("/", get(|| async {}))
                .route_layer(builder_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let app_macro = Router::new()
                .route("/", get(|| async {}))
                .route_layer(macro_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let res_builder = request(&app_builder, "/", None).await;
            let res_macro = request(&app_macro, "/", None).await;

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[tokio::test]
        async fn test_permission_required_parity_authenticated() {
            let builder_layer = RequireBuilder::<TestBackend>::new()
                .predicate(SimplePredicate::new().with_permissions(vec!["test.read"]))
                .build();
            let macro_layer = permission_required!(TestBackend, "test.read");

            let app_builder = Router::new()
                .route("/", get(|| async {}))
                .route_layer(builder_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let app_macro = Router::new()
                .route("/", get(|| async {}))
                .route_layer(macro_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let cookie_builder = login_cookie(&app_builder).await;
            let cookie_macro = login_cookie(&app_macro).await;

            let res_builder = request(&app_builder, "/", Some(&cookie_builder)).await;
            let res_macro = request(&app_macro, "/", Some(&cookie_macro)).await;

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[tokio::test]
        async fn test_permission_required_parity_redirect() {
            let builder_layer = RequireBuilder::<TestBackend>::new()
                .predicate(SimplePredicate::new().with_permissions(vec!["test.read"]))
                .fallback(RedirectFallback::new().login_url("/login"))
                .build();
            let macro_layer =
                permission_required!(TestBackend, login_url = "/login", "test.read");

            let app_builder = Router::new()
                .route("/", get(|| async {}))
                .route_layer(builder_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let app_macro = Router::new()
                .route("/", get(|| async {}))
                .route_layer(macro_layer)
                .route(
                    "/login",
                    get(|auth_session: AuthSession<TestBackend>| async move {
                        auth_session.login(&User).await.unwrap();
                    }),
                )
                .layer(auth_layer!());

            let res_builder = request(&app_builder, "/", None).await;
            let res_macro = request(&app_macro, "/", None).await;

            assert_eq!(res_builder.status(), res_macro.status());
            assert_eq!(location(&res_builder), location(&res_macro));
        }
    }

    #[tokio::test]
    async fn test_login_required_with_login_url() {
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(RedirectFallback::new().login_url("/login"))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
        let fallback = RedirectFallback::new()
            .redirect_field("next_uri")
            .login_url("/signin");

        let require = RequireBuilder::<TestBackend>::new()
            .fallback(fallback)
            .build();
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/signin",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
    async fn test_login_required_with_response_fallback() {
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(|_| async { StatusCode::GONE.into_response() })
            .fallback(SimpleResponseFallback::text(StatusCode::GONE, "test"))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/signin",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::GONE);

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
    async fn test_login_required_with_custom_fallback() {
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(|_| async { StatusCode::GONE.into_response() })
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/signin",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::GONE);

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
        let require = RequireBuilder::<TestBackend>::new()
            .predicate(SimplePredicate::new().with_permissions(permissions))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
    async fn test_permission_required_multiple_permissions() {
        let permissions: Vec<&str> = vec!["test.read", "test.write"];
        let require = RequireBuilder::<TestBackend>::new()
            .predicate(SimplePredicate::new().with_permissions(permissions))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
    async fn test_permission_required_with_login_url() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(RedirectFallback::new().login_url("/login"))
            .predicate(SimplePredicate::new().with_permissions(permissions))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(
                RedirectFallback::new()
                    .redirect_field("next_uri")
                    .login_url("/signin"),
            )
            .predicate(SimplePredicate::new().with_permissions(permissions))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/signin",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
        let require = RequireBuilder::<TestBackend>::new()
            .predicate(SimplePredicate::new().with_permissions(permissions))
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_redirect_uri_query() {
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(RedirectFallback::new().login_url("/login"))
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
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(RedirectFallback::new().login_url("/login?foo=bar&foo=baz"))
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
        let require = RequireBuilder::<TestBackend>::new()
            .fallback(
                RedirectFallback::new()
                    .redirect_field("next_url")
                    .login_url("/login?next_url=%2Fdashboard"),
            )
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

        let require = RequireBuilder::<TestBackend>::new()
            .fallback(RedirectFallback::new().login_url("/login?next=%2Fdashboard"))
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
        let require = Require::<TestBackend>::builder()
            .fallback(RedirectFallback::new().login_url("/login"))
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

    #[tokio::test]
    async fn test_login_required_perm_with_state() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let f = |backend: TestBackend, user: User, state: TestState| {
            verify_permissions(backend, user, state)
        };
        let require_login = Require::<TestBackend, TestState>::builder_with_state(state.clone())
            .fallback(RedirectFallback::new().login_url("/login"))
            .restrict(|_| async { StatusCode::UNAUTHORIZED.into_response() })
            .predicate(f)
            .build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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
        let f = |backend: TestBackend, user: User, state: TestState| {
            verify_permissions(backend, user, state)
        };

        let re = RequireBuilder::<TestBackend, TestState>::new_with_state(state.clone()).fallback(
            RedirectFallback::new()
                .redirect_field("next_url")
                .login_url("/login?next_url=%2Fdashboard"),
        );
        let pre = re.predicate(f);
        let require_login = pre.build();

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(require_login)
            .route(
                "/signin",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
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

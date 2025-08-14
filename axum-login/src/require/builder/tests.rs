#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::{
        http::{header, Request, Response, StatusCode},
        Router,
    };
    use std::collections::HashSet;
    use tower::ServiceExt;
    use tower_cookies::cookie;
    use tower_sessions::SessionManagerLayer;
    use tower_sessions_sqlx_store::{sqlx::SqlitePool, SqliteStore};

    use crate::require::builder::params::{Predicate, Rstr};
    use crate::require::builder::RequireBuilder;
    use crate::require::fallback::{  RedirectFallback};
    use crate::require::Require;
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
        let require_login: Require<Backend> = RequireBuilder::new()
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
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
        let fallback = RedirectFallback {
            redirect_field: Some("next_uri".to_string()),
            login_url: Some("/signin".to_string()),
        };
        let require = RequireBuilder::<Backend>::new()
            .fallback(fallback)
            // .predicate(Predicate::Params {
            //     permissions: permissions.iter().map(|&p| p.into()).collect(),
            // })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: Some("next_uri".to_string()),
                login_url: Some("/signin".to_string()),
            })
            .predicate(Predicate::Params {
                permissions: permissions.iter().map(|&p| p.into()).collect(),
            })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login?foo=bar&foo=baz".to_string()),
            })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: Some("next_url".to_string()),
                login_url: Some("/login?next_url=%2Fdashboard".to_string()),
            })
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

        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login?next=%2Fdashboard".to_string()),
            })
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
        let require = RequireBuilder::<Backend>::new()
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
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

    // #[tokio::test]
    // async fn test_require_builder_all_combinations() {
    //     //TODO: add tests with state
    //     #[derive(Clone)]
    //     struct TestState {
    //         req_perm: Vec<String>,
    //     }
    //
    //     let state = TestState {
    //         req_perm: vec!["test.read".into()],
    //     };
    //
    //     // Predicate factory functions
    //     let predicate_factories: Vec<Box<dyn Fn() -> Predicate<Backend, TestState>>> = vec![
    //         Box::new(|| {
    //             Predicate::from_closure(|_b: Backend, _u: User, _s: TestState| async { true })
    //         }),
    //         Box::new(|| Predicate::Params {
    //             permissions: vec!["test.read".into()],
    //         }),
    //     ];
    //
    //     // Restrict factory functions
    //     let restrict_factories: Vec<Box<dyn Fn() -> Rstr<Body>>> = vec![
    //         Box::new(|| {
    //             Rstr::from_closure(|_req| async {
    //                 Response::builder()
    //                     .status(StatusCode::FORBIDDEN)
    //                     .body("Forbidden".into())
    //                     .unwrap()
    //             })
    //         }),
    //         Box::new(|| Rstr::Params {
    //             i_dunno: Some("param".to_string()),
    //         }),
    //     ];
    //
    //     for pred_factory in predicate_factories {
    //         for restrict_factory in &restrict_factories {
    //             // Create fresh instances
    //             let pred = pred_factory();
    //             let fallback =
    //                 |_req| async {
    //                     Response::builder()
    //                         .status(StatusCode::UNAUTHORIZED)
    //                         .body("Unauthorized".into())
    //                         .unwrap()
    //                 };
    //             let restrict = restrict_factory();
    //
    //             // Build
    //             let require: Require<Backend, TestState, Body> = RequireBuilder::new()
    //                 .predicate(pred)
    //                 // .fallback(fallback)
    //                 .on_restrict(restrict)
    //                 .state(state.clone())
    //                 .build();
    //
    //             // Test fallback handler response
    //             let req = axum::http::Request::builder()
    //                 .uri("/")
    //                 .body(Body::empty())
    //                 .unwrap();
    //
    //             let fallback_resp = (require.fallback)(req).await;
    //             assert!(matches!(
    //                     fallback_resp.status(),
    //                     StatusCode::UNAUTHORIZED
    //                         | StatusCode::TEMPORARY_REDIRECT
    //                         | StatusCode::INTERNAL_SERVER_ERROR
    //                 ));
    //         }
    //     }
    // }

    #[tokio::test]
    async fn test_login_required_perm_with_state() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let f = |backend, user, state| verify_permissions(backend, user, state);
        let require_login = RequireBuilder::new_with_state(state.clone())
            .fallback(RedirectFallback {
                redirect_field: None,
                login_url: Some("/login".to_string()),
            })
            .predicate(Predicate::from_closure(f))
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

        let require_login = RequireBuilder::new_with_state(state.clone())
            .fallback(RedirectFallback {
                redirect_field: Some("next_url".to_string()),
                login_url: Some("/login?next_url=%2Fdashboard".to_string()),
            })
            // .fallback(MissingAuthHandlerParams::from_handler(|_, _| async {
            //     StatusCode::UNAUTHORIZED.into_response()
            // }))
            .predicate(Predicate::from_closure(|backend, user, state| {
                verify_permissions(backend, user, state)
            }))
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

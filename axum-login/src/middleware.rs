use axum::http::{self, Uri};

fn update_query(uri: &Uri, new_query: String) -> Result<Uri, http::Error> {
    let query = form_urlencoded::parse(uri.query().map(|q| q.as_bytes()).unwrap_or_default());
    let updated_query = form_urlencoded::Serializer::new(new_query)
        .extend_pairs(query)
        .finish();

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(format!("{}?{}", uri.path(), updated_query).parse()?);

    Ok(Uri::from_parts(parts)?)
}

/// This is intended for internal use only and subject to change in the future
/// without warning!
#[doc(hidden)]
pub fn url_with_redirect_query(
    url: &str,
    redirect_field: &str,
    redirect_uri: Uri,
) -> Result<Uri, http::Error> {
    let uri = url.parse::<Uri>()?;

    if uri.query().is_some_and(|q| q.contains(redirect_field)) {
        return Ok(uri);
    };

    let redirect_uri_string = redirect_uri.to_string();
    let redirect_uri_encoded = urlencoding::encode(&redirect_uri_string);
    let redirect_query = format!("{}={}", redirect_field, redirect_uri_encoded);

    update_query(&uri, redirect_query)
}

/// Login predicate middleware.
///
/// Requires that the user is authenticated.
#[macro_export]
macro_rules! login_required {
    ($backend_type:ty) => {{
        async fn is_authenticated(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            auth_session.user.is_some()
        }

        $crate::predicate_required!(
            is_authenticated,
            $crate::axum::http::StatusCode::UNAUTHORIZED
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        async fn is_authenticated(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            auth_session.user.is_some()
        }

        $crate::predicate_required!(
            is_authenticated,
            login_url = $login_url,
            redirect_field = $redirect_field
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr) => {
        $crate::login_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next"
        )
    };
}

/// Permission predicate middleware.
///
/// Requires that the specified permissions, either user or group or both, are
/// all assigned to the user.
#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr, $($perm:expr),+ $(,)?) => {{
        use $crate::AuthzBackend;

        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            if let Some(ref user) = auth_session.user {
                auth_session.backend.has_all_perm(user, vec![$($perm.into(),)+]).await.unwrap_or(false)
            } else {
                false
            }
        }

        $crate::predicate_required!(
            is_authorized,
            login_url = $login_url,
            redirect_field = $redirect_field
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, $($perm:expr),+ $(,)?) => {
        $crate::permission_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next",
            $($perm),+
        )
    };

    ($backend_type:ty, $($perm:expr),+ $(,)?) => {{
        use $crate::AuthzBackend;

        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            if let Some(ref user) = auth_session.user {
                auth_session.backend.has_all_perm(user, vec![$($perm.into(),)+]).await.unwrap_or(false)
            } else {
                false
            }
        }

        $crate::predicate_required!(
            is_authorized,
            $crate::axum::http::StatusCode::FORBIDDEN
        )
    }};
}

/// Predicate middleware.
///
/// Can be specified with a login URL and next redirect field or an alternative
/// which implements [`IntoResponse`](axum::response::IntoResponse).
///
/// When the predicate passes, the request processes normally. On failure,
/// either a redirect to the specified login URL is issued or the alternative is
/// used as the response.
#[macro_export]
macro_rules! predicate_required {
    ($predicate:expr, $alternative:expr) => {{
        use $crate::axum::{
            middleware::{from_fn, Next},
            response::IntoResponse,
        };

        from_fn(
            |auth_session: $crate::AuthSession<_>, req, next: Next| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    $alternative.into_response()
                }
            },
        )
    }};

    ($predicate:expr, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        use $crate::axum::{
            extract::OriginalUri,
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession<_>,
             OriginalUri(original_uri): OriginalUri,
             req,
             next: Next| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    match $crate::url_with_redirect_query(
                        $login_url,
                        $redirect_field,
                        original_uri
                    ) {
                        Ok(login_url) => {
                            Redirect::temporary(&login_url.to_string()).into_response()
                        }

                        Err(err) => {
                            $crate::tracing::error!(err = %err);
                            $crate::axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
            },
        )
    }};
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{header, Request, Response, StatusCode},
        Router,
    };
    use tower::ServiceExt;
    use tower_cookies::cookie;
    use tower_sessions::SessionManagerLayer;
    use tower_sessions_sqlx_store::{sqlx::SqlitePool, SqliteStore};

    use crate::{AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend};

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

    #[async_trait]
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

    #[async_trait]
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

    macro_rules! auth_layer {
        () => {{
            let pool = SqlitePool::connect(":memory:").await.unwrap();
            let session_store = SqliteStore::new(pool.clone());
            session_store.migrate().await.unwrap();

            let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

            AuthManagerLayerBuilder::new(Backend, session_layer).build()
        }};
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

    #[tokio::test]
    async fn test_login_required() {
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(Backend))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(Backend, login_url = "/login"))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(
                Backend,
                login_url = "/signin",
                redirect_field = "next_uri"
            ))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(Backend, "test.read"))
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(Backend, "test.read", "test.write"))
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(
                Backend,
                login_url = "/login",
                "test.read"
            ))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(
                Backend,
                login_url = "/signin",
                redirect_field = "next_uri",
                "test.read"
            ))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(
                Backend,
                "test.read",
                "test.write",
                "admin.read"
            ))
            .route(
                "/login",
                axum::routing::get(|mut auth_session: AuthSession<Backend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer!());

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(Backend, login_url = "/login"))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(
                Backend,
                login_url = "/login?foo=bar&foo=baz"
            ))
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
        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(
                Backend,
                login_url = "/login?next_url=%2Fdashboard",
                redirect_field = "next_url"
            ))
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

        let app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(
                Backend,
                login_url = "/login?next=%2Fdashboard"
            ))
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
        let nested = Router::new()
            .route("/foo", axum::routing::get(|| async {}))
            .route_layer(login_required!(Backend, login_url = "/login"));
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
}

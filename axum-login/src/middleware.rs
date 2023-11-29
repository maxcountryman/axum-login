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
            $crate::http::StatusCode::UNAUTHORIZED
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
/// Permission predicate middleware.
#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr, $($perm:expr),+ $(,)?) => {{
        use $crate::AuthzBackend;

        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            use $crate::AuthzBackend;
            if let Some(ref user) = auth_session.user {
                let mut has_all_permissions = true;
                $(
                    has_all_permissions = has_all_permissions &&
                        auth_session.backend.has_perm(user, $perm.into()).await.unwrap_or(false);
                )+
                has_all_permissions
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
                let mut has_all_permissions = true;
                $(
                    has_all_permissions = has_all_permissions &&
                        auth_session.backend.has_perm(user, $perm.into()).await.unwrap_or(false);
                )+
                has_all_permissions
            } else {
                false
            }
        }

        $crate::predicate_required!(
            is_authorized,
            $crate::http::StatusCode::FORBIDDEN
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
            response::{IntoResponse, Redirect},
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
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession<_>, req, next: Next| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    let uri = req.uri().to_string();
                    let next = $crate::urlencoding::encode(&uri);
                    let redirect_url = format!("{}?{}={}", $login_url, $redirect_field, next);
                    Redirect::temporary(&redirect_url).into_response()
                }
            },
        )
    }};
}

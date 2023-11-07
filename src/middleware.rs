/// A middleware that requires login.
#[macro_export]
macro_rules! login_required {
    ($backend_type:ty) => {{
        async fn is_authenticated(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            auth_session.user.is_some()
        }

        $crate::predicate_required!(
            $backend_type,
            is_authenticated,
            ::http::StatusCode::UNAUTHORIZED
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        async fn is_authenticated(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            auth_session.user.is_some()
        }

        $crate::predicate_required!(
            $backend_type,
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

/// A middleware that requires the given permissions.
#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty, $($perm:expr),+) => {{
        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            if let Some(ref user) = auth_session.user {
                let mut has_all_permissions = true;
                $(
                    has_all_permissions = has_all_permissions &&
                        auth_session.backend.has_perm(user, $perm).await.unwrap_or(false);
                )+
                has_all_permissions
            } else {
                false
            }
        }

        $crate::predicate_required!(
            is_authorized,
            $backend_type,
            ::http::StatusCode::FORBIDDEN
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr, $($perm:expr),+) => {{
        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> bool {
            if let Some(ref user) = auth_session.user {
                let mut has_all_permissions = true;
                $(
                    has_all_permissions = has_all_permissions &&
                        auth_session.backend.has_perm(user, $perm).await.unwrap_or(false);
                )+
                has_all_permissions
            } else {
                false
            }
        }

        $crate::predicate_required!(
            $backend_type,
            is_authorized,
            login_url = $login_url,
            redirect_field = $redirect_field
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, $($perm:expr),+) => {
        $crate::permission_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next",
            $($perm),+
        )
    };
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
    ($backend_type:ty, $predicate:expr, $alternative:expr) => {{
        use axum::{
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession<$backend_type>, req, next: Next<_>| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    $alternative.into_response()
                }
            },
        )
    }};

    ($backend_type:ty, $predicate:expr, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        use axum::{
            middleware::{from_fn, Next},
            response::{IntoResponse, Redirect},
        };

        from_fn(
            |auth_session: $crate::AuthSession<$backend_type>, req, next: Next<_>| async move {
                if $predicate(auth_session).await {
                    next.run(req).await
                } else {
                    let uri = req.uri().to_string();
                    let next = urlencoding::encode(&uri);
                    let redirect_url = format!("{}?{}={}", $login_url, $redirect_field, next);
                    Redirect::to(&redirect_url).into_response()
                }
            },
        )
    }};
}

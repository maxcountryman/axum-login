#[macro_export]
macro_rules! login_required {
    ($backend_type:ty, login_url = $login_url:expr) => {
        $crate::predicate_required!(
            $backend_type,
            $login_url,
            "next",
            |auth_session: $crate::AuthSession<$backend_type>| async move {
                auth_session.user.is_some()
            }
        );
    };

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {
        $crate::predicate_required!(
            $backend_type,
            $login_url,
            $redirect_field,
            |auth_session: $crate::AuthSession<$backend_type>| async move {
                auth_session.user.is_some()
            }
        );
    };
}

#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty,  login_url = $login_url:expr, $($perm:expr),+) => {
        $crate::predicate_required!(
            $backend_type,
            $login_url,
            "next",
            |auth_session: $crate::AuthSession<$backend_type>| async move {
                if let Some(ref user) = auth_session.user {
                    let mut has_all_permissions = true;
                    $(
                        has_all_permissions = has_all_permissions && auth_session.backend.has_perm(user, $perm).await.unwrap_or(false);
                    )+
                    has_all_permissions

                } else {
                    false
                }
            }
        );
    };

    ($backend_type:ty, login_url = $login_url:expr, $perms:expr) => {
        $crate::permission_required!($backend_type, login_url = $login_url, $perms);
    };
}

#[macro_export]
macro_rules! predicate_required {
    ($backend_type:ty, $login_url:expr, $redirect_field:expr, $predicate:expr) => {{
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

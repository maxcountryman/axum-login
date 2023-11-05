#[macro_export]
macro_rules! login_required {
    ($backend_type:ty, login_url = $login_url:expr) => {
        $crate::login_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next"
        )
    };

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        async fn is_authenticated(
            auth_session: $crate::AuthSession<$backend_type>,
        ) -> Result<bool, ()> {
            Ok(auth_session.user.is_some())
        }

        $crate::predicate_required!($backend_type, $login_url, $redirect_field, is_authenticated)
    }};
}

#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr, $($perm:expr),+) => {{
        async fn is_authorized(auth_session: $crate::AuthSession<$backend_type>) -> Result<bool, ::http::StatusCode> {
            if let Some(ref user) = auth_session.user {
                let mut has_all_permissions = true;
                $(
                    has_all_permissions = has_all_permissions &&
                        auth_session.backend.has_perm(user, $perm).await.unwrap_or(false);
                )+
                Ok(has_all_permissions)
            } else {
                Ok(false)
            }
        }

        $crate::predicate_required!(
            $backend_type,
            $login_url,
            $redirect_field,
            is_authorized
        )
    }};

    ($backend_type:ty, login_url = $login_url:expr, $($perm:expr),+) => {{
        $crate::permission_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next",
            $($perm),+
        )
    }};
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
                match $predicate(auth_session).await {
                    Ok(true) => next.run(req).await,
                    Ok(false) => {
                        let uri = req.uri().to_string();
                        let next = urlencoding::encode(&uri);
                        let redirect_url = format!("{}?{}={}", $login_url, $redirect_field, next);
                        Redirect::to(&redirect_url).into_response()
                    }
                    Err(res) => res.into_response(),
                }
            },
        )
    }};
}

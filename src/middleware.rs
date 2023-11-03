use axum::{middleware::Next, response::Response};
use http::Request;

use crate::{AccessController, LoginSession};

/// Requires the user is authenticated, which is indicated by the presense of a
/// user on the login session.
///
/// This is intended to be used with
/// [`middleware::from_fn`](axum::middleware::from_fn).
pub async fn require_authn<Controller: AccessController, B: Send>(
    login_session: LoginSession<Controller>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    if login_session.user.is_some() {
        next.run(req).await
    } else {
        login_session.access_controller.authn_failure(req).await
    }
}

/// Requires the user is authorized according to the implementation of
/// [`is_authz`](UserStore::is_authz).
///
/// This is intended to be used with
/// [`middleware::from_fn`](axum::middleware::from_fn).
pub async fn require_authz<Controller: AccessController, B: Send>(
    login_session: LoginSession<Controller>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    match login_session.user {
        Some(user) if login_session.access_controller.is_authz(&user).await => next.run(req).await,
        _ => {
            login_session
                .access_controller
                .authz_failure(req, login_session.user)
                .await
        }
    }
}

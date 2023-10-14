//! Middleware that leverage `UserStore` in order to ensure authentication and
//! authorization conditions are met.
use axum::{middleware::Next, response::Response};
use http::Request;

use crate::{Auth, UserStore};

/// Requires the user is authenticated according to the implementation of
/// [`is_authn`](UserStore.is_authn).
///
/// This is intended to be used with
/// [`middleware::from_fn`](axum::middleware::from_fn).
pub async fn require_authn<Users, B>(auth: Auth<Users>, req: Request<B>, next: Next<B>) -> Response
where
    Users: UserStore,
    B: Send,
{
    match auth.user {
        Some(user) if auth.user_store.is_authn(&user).await => next.run(req).await,
        _ => auth.user_store.authn_failure(req).await,
    }
}

/// Requires the user is authorized according to the implementation of
/// [`is_authz`](UserStore::is_authz).
///
/// This is intended to be used with
/// [`middleware::from_fn`](axum::middleware::from_fn).
pub async fn require_authz<Users: UserStore, B: Send>(
    auth: Auth<Users>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    match auth.user {
        Some(user) if auth.user_store.is_authz(&user).await => next.run(req).await,
        _ => auth.user_store.authz_failure(req, auth.user).await,
    }
}

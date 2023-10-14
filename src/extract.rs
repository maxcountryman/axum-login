use async_trait::async_trait;
use axum::{extract::FromRequestParts, middleware::Next, response::Response};
use http::{request::Parts, Request, StatusCode};

use crate::{service::Auth, user_store::UserStore};

#[async_trait]
impl<S, Users> FromRequestParts<S> for Auth<Users>
where
    S: Send + Sync,
    Users: UserStore + Send + Sync,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Auth<_>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract auth. Is `LoginManagerLayer` enabled?",
        ))
    }
}

pub async fn require_authn<Users, B>(auth: Auth<Users>, req: Request<B>, next: Next<B>) -> Response
where
    Users: UserStore,
    B: Send,
{
    match auth.user {
        Some(user) if auth.user_store.is_authenticated(&user).await => next.run(req).await,
        _ => auth.user_store.authentication_failure(req).await,
    }
}

pub async fn require_authz<Users: UserStore, B: Send>(
    auth: Auth<Users>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    match auth.user {
        Some(user) if auth.user_store.is_authorized(&user).await => next.run(req).await,
        _ => auth.user_store.authorization_failure(req, auth.user).await,
    }
}

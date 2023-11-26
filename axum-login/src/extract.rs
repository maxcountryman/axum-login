use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use crate::{AuthSession, AuthnBackend};

#[async_trait]
impl<S, Backend> FromRequestParts<S> for AuthSession<Backend>
where
    S: Send + Sync,
    Backend: AuthnBackend + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthSession<_>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract auth session. Is `AuthManagerLayer` enabled?",
        ))
    }
}

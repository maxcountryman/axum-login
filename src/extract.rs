use async_trait::async_trait;
use axum::extract::FromRequestParts;
use http::{request::Parts, StatusCode};

use crate::{AuthBackend, AuthSession};

#[async_trait]
impl<S, Backend> FromRequestParts<S> for AuthSession<Backend>
where
    S: Send + Sync,
    Backend: AuthBackend + Send + Sync + 'static,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthSession<_>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract auth. Is `LoginManagerLayer` enabled?",
        ))
    }
}

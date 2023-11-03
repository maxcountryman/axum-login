use async_trait::async_trait;
use axum::extract::FromRequestParts;
use http::{request::Parts, StatusCode};

use crate::{AccessController, LoginSession};

#[async_trait]
impl<S, Controller> FromRequestParts<S> for LoginSession<Controller>
where
    S: Send + Sync,
    Controller: AccessController + Send + Sync,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<LoginSession<_>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract auth. Is `LoginManagerLayer` enabled?",
        ))
    }
}

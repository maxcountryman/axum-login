//! An extractor for [`Auth`] which allows applications to authenticate users.
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use http::{request::Parts, StatusCode};

use crate::{Auth, UserStore};

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

use async_trait::async_trait;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait UserStore: std::fmt::Debug + Clone + Send + Sync + 'static {
    type User: Clone + Send + Sync;
    type UserId: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;
    type Error: std::error::Error + Send + Sync;

    /// Load a user by some given ID.
    ///
    /// This method can be used to load a user from some kind of storage layer,
    /// like a database or an external identity provider. Here the user ID
    /// can be anything that identifies a unique user.
    async fn load(&self, user_id: &Self::UserId) -> Result<Option<Self::User>, Self::Error>;

    async fn is_authenticated(&self, _user: &Self::User) -> bool {
        false
    }

    async fn is_authorized(&self, _user: &Self::User) -> bool {
        false
    }

    async fn authentication_failure<B: Send>(&self, _req: Request<B>) -> Response {
        (StatusCode::UNAUTHORIZED, "User is not authenticated.").into_response()
    }

    async fn authorization_failure<B: Send>(
        &self,
        _req: Request<B>,
        _user: Option<Self::User>,
    ) -> Response {
        (
            StatusCode::FORBIDDEN,
            "User is not authorized to access this resource.",
        )
            .into_response()
    }
}

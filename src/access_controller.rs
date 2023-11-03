use async_trait::async_trait;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

/// A trait that provides access controls over an associated user type.
#[async_trait]
pub trait AccessController: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The user type to control.
    type User: Clone + Send + Sync;

    /// The type of a user's identifying feature.
    type UserId: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// An error type that can occur when loading a user.
    type Error: std::error::Error + Send + Sync;

    /// Loads a user by some identifying feature.
    async fn load_user(&self, user_id: &Self::UserId) -> Result<Option<Self::User>, Self::Error>;

    /// Returns `true` if the user is authorized.
    ///
    /// By default returns `false`.
    ///
    /// A custom implementation **must** be provided if authorization flows are
    /// desired.
    async fn is_authz(&self, _user: &Self::User) -> bool {
        false
    }

    /// A response that will be used when authentication fails.
    ///
    /// By default this will return an unauthorized response.
    async fn authn_failure<B: Send>(&self, _req: Request<B>) -> Response {
        (StatusCode::UNAUTHORIZED, "User is not authenticated.").into_response()
    }

    /// A response that will be used when authorization fails.
    ///
    /// By default this will return a forbidden response.
    async fn authz_failure<B: Send>(
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

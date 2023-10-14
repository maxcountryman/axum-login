use async_trait::async_trait;
use axum::response::{IntoResponse, Response};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

/// A trait that provides an interface for loading a user from some store as
/// well as methods for defining whether a user is autheniticated, authorized,
/// and respective methods for generating responses for when they are not.
#[async_trait]
pub trait UserStore: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The user type this store will load and otherwise manage.
    type User: Clone + Send + Sync;

    /// The type of a user's identifier.
    type UserId: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// An error type that can occur when loading a user from the store.
    type Error: std::error::Error + Send + Sync;

    /// Loads a user by some identifier.
    ///
    /// This loads a user from the store. The only requirement is
    /// that there be some unique way of identifying the user, for instance
    /// by an ID, email address, etc.
    ///
    /// Note that the specific implementation of the store could be anything,
    /// for instance a database or an external identity provider.
    async fn load(&self, user_id: &Self::UserId) -> Result<Option<Self::User>, Self::Error>;

    /// Returns `true` if the user is authenticated.
    ///
    /// By default returns `false`. A custom implementation **must** be provided
    /// if authentication is desired.
    async fn is_authn(&self, _user: &Self::User) -> bool {
        false
    }

    /// Returns `true` if the user is authorized.
    ///
    /// By default returns `false`. A customer implementation **must** be
    /// provided if authorization flows are desired.
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

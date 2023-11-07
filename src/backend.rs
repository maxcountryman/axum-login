use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    hash::Hash,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Type alias for the backend user's ID.
pub type UserId<Backend> = <<Backend as AuthnBackend>::User as AuthUser>::Id;

/// A user which can be identified, authenticated, and authorized.
///
/// # Examples
///
/// ```rust
/// use axum_login::AuthUser;
///
/// #[derive(Debug, Clone)]
/// struct User {
///     id: i64,
///     pw_hash: Vec<u8>,
/// }
///
/// impl AuthUser for User {
///     type Id = i64;
///
///     fn id(&self) -> Self::Id {
///         self.id
///     }
///
///     fn session_auth_hash(&self) -> &[u8] {
///         &self.pw_hash
///     }
/// }
/// ```
pub trait AuthUser: Debug + Clone + Send + Sync {
    /// An identifying feature of the user.
    type Id: Debug + Display + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    /// Returns some identifying feature of the user.
    fn id(&self) -> Self::Id;

    /// Returns a hash that's used by the session to verify the session is
    /// valid.
    ///
    /// For example, if users have passwords, this method might return a
    /// cryptographically secure hash of that password.
    fn session_auth_hash(&self) -> &[u8];
}

/// A backend which can authenticate users.
///
/// Backends must implement:
///
/// 1. [`authenticate`](AuthnBackend::authenticate), a method for authenticating
///    users with credentials and,
/// 2. [`get_user`](AuthnBackend::get_user) a method for getting a user by an
///    identifying feature.
///
/// With these two methods, users may be authenticated and later retrieved via
/// the backend.
///
/// # Examples
///
/// ```rust
/// use std::collections::HashMap;
///
/// use async_trait::async_trait;
/// use axum_login::{AuthUser, AuthnBackend, UserId};
///
/// #[derive(Debug, Clone)]
/// struct User {
///     id: i64,
///     pw_hash: Vec<u8>,
/// }
///
/// impl AuthUser for User {
///     type Id = i64;
///
///     fn id(&self) -> Self::Id {
///         self.id
///     }
///
///     fn session_auth_hash(&self) -> &[u8] {
///         &self.pw_hash
///     }
/// }
///
/// #[derive(Clone)]
/// struct Backend {
///     users: HashMap<i64, User>,
/// }
///
/// #[derive(Clone)]
/// struct Credentials {
///     user_id: i64,
/// }
///
/// #[async_trait]
/// impl AuthnBackend for Backend {
///     type User = User;
///     type Credentials = Credentials;
///     type Error = std::convert::Infallible;
///
///     async fn authenticate(
///         &self,
///         Credentials { user_id }: Self::Credentials,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(self.users.get(&user_id).cloned())
///     }
///
///     async fn get_user(
///         &self,
///         user_id: &UserId<Self>,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(self.users.get(user_id).cloned())
///     }
/// }
/// ```
#[async_trait]
pub trait AuthnBackend: Clone + Send + Sync {
    /// Authenticating user type.
    type User: AuthUser;

    /// Credential type used for authentication.
    type Credentials: Clone + Send + Sync;

    /// An error which can occur during authentication and authorization.
    type Error: std::error::Error + Send + Sync;

    /// Authenticates the given credentials with the backend.
    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error>;

    /// Gets the user by provided ID from the backend.
    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error>;
}

/// A backend which can authorize users.
///
/// Backends must implement `AuthnBackend`.
#[async_trait]
pub trait AuthzBackend: Clone + Send + Sync
where
    Self: AuthnBackend,
{
    /// Permission type.
    type Permission: Hash + Eq + Clone + Send + Sync;

    /// Gets the permissions for the provided user.
    async fn get_user_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    /// Gets the group permissions for the provided user.
    async fn get_group_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    /// Gets all permissions for the provided user.
    async fn get_all_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let mut all_perms = HashSet::new();
        all_perms.extend(self.get_user_permissions(user).await?);
        all_perms.extend(self.get_group_permissions(user).await?);
        Ok(all_perms)
    }

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn has_perm(
        &self,
        user: &Self::User,
        perm: Self::Permission,
    ) -> Result<bool, Self::Error> {
        Ok(self.get_all_permissions(user).await?.contains(&perm))
    }
}

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
    type Credentials: Send + Sync;

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
pub trait AuthzBackend
where
    Self: AuthnBackend,
{
    /// Permission type.
    type Permission: Hash + Eq + Send + Sync;

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

    /// Returns a result which is `true` when the provided user has all the provided
    /// permissions and otherwise is `false`.
    async fn has_all_perm(
        &self,
        user: &Self::User,
        mut permissions: Vec<Self::Permission>,
    ) -> Result<bool, Self::Error> {
        if permissions.is_empty() {
            return Ok(true);
        }

        if permissions.len() == 1 {
            return self.has_perm(user, permissions.remove(0)).await;
        }

        let db_permissions = self.get_all_permissions(user).await?;

        let has_all = permissions.iter().all(|p| db_permissions.contains(&p));

        Ok(has_all)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestUser {
        id: i64,
        pw_hash: Vec<u8>,
    }

    impl AuthUser for TestUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &self.pw_hash
        }
    }

    #[derive(Clone)]
    struct TestBackend {
        users: HashMap<i64, TestUser>,
        user_permissions: HashMap<i64, HashSet<String>>,

        groups: HashMap<String, HashSet<i64>>,
        group_permissions: HashMap<String, HashSet<String>>,
    }

    impl TestBackend {
        fn new() -> Self {
            TestBackend {
                users: HashMap::new(),
                user_permissions: HashMap::new(),

                groups: HashMap::new(),
                group_permissions: HashMap::new(),
            }
        }

        fn add_user(&mut self, user: TestUser, permissions: Vec<String>) {
            self.users.insert(user.id, user.clone());
            self.user_permissions
                .insert(user.id, permissions.into_iter().collect());
        }

        fn add_group(&mut self, group: String, permissions: Vec<String>) {
            self.groups.insert(group.clone(), HashSet::new());
            self.group_permissions
                .insert(group, permissions.into_iter().collect());
        }

        fn add_user_to_group(&mut self, user: TestUser, group: String) {
            self.groups.entry(group).and_modify(|members| {
                members.insert(user.id);
            });
        }
    }

    #[async_trait]
    impl AuthnBackend for TestBackend {
        type User = TestUser;
        type Credentials = i64; // Simplified for testing
        type Error = std::convert::Infallible;

        async fn authenticate(
            &self,
            user_id: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(self.users.get(&user_id).cloned())
        }

        async fn get_user(
            &self,
            user_id: &UserId<Self>,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(self.users.get(user_id).cloned())
        }
    }

    #[async_trait]
    impl AuthzBackend for TestBackend {
        type Permission = String;

        async fn get_user_permissions(
            &self,
            user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            Ok(self
                .user_permissions
                .get(&user.id)
                .cloned()
                .unwrap_or_default())
        }

        async fn get_group_permissions(
            &self,
            user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            let belongs_to = self
                .groups
                .iter()
                .filter_map(|(group, members)| {
                    if members.contains(&user.id) {
                        Some(group)
                    } else {
                        None
                    }
                })
                .collect::<HashSet<_>>();

            let group_permissions = self
                .group_permissions
                .iter()
                .filter_map(|(group, permissions)| {
                    if belongs_to.contains(group) {
                        Some(permissions)
                    } else {
                        None
                    }
                })
                .flatten()
                .cloned()
                .collect::<HashSet<_>>();

            Ok(group_permissions)
        }
    }

    #[tokio::test]
    async fn test_authenticate() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec![]);

        let authenticated_user = backend.authenticate(1).await.unwrap();
        assert_eq!(authenticated_user, Some(user));
    }

    #[tokio::test]
    async fn test_authenticate_failure() {
        let backend = TestBackend::new();

        assert!(backend.authenticate(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_get_user() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec![]);

        let retrieved_user = backend.get_user(&1).await.unwrap();
        assert_eq!(retrieved_user, Some(user));
    }

    #[tokio::test]
    async fn test_get_user_permissions() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["read".to_string(), "write".to_string()]);

        let permissions = backend.get_user_permissions(&user).await.unwrap();
        assert_eq!(
            permissions,
            ["read".to_string(), "write".to_string()]
                .iter()
                .cloned()
                .collect()
        );
    }

    #[tokio::test]
    async fn test_get_group_permissions() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };

        let admin = TestUser {
            id: 0,
            pw_hash: vec![1, 2, 3, 4],
        };

        let mut backend = TestBackend::new();

        backend.add_user(user.clone(), vec!["other".to_string()]);
        backend.add_group(
            "users".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );
        backend.add_user_to_group(user.clone(), "users".to_string());

        backend.add_user(admin.clone(), vec![]);
        backend.add_group("admins".to_string(), vec!["delete".to_string()]);
        backend.add_user_to_group(admin.clone(), "users".to_string());
        backend.add_user_to_group(admin.clone(), "admins".to_string());

        // User permissions.
        let user_perms = backend.get_group_permissions(&user).await.unwrap();
        assert_eq!(
            user_perms,
            ["read".to_string(), "write".to_string()]
                .iter()
                .cloned()
                .collect()
        );

        let admin_perms = backend.get_group_permissions(&admin).await.unwrap();
        assert_eq!(
            admin_perms,
            [
                "read".to_string(),
                "write".to_string(),
                "delete".to_string()
            ]
            .iter()
            .cloned()
            .collect()
        );
    }

    #[tokio::test]
    async fn test_get_all_permissions() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["other".to_string()]);
        backend.add_group(
            "users".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );
        backend.add_user_to_group(user.clone(), "users".to_string());

        let permissions = backend.get_all_permissions(&user).await.unwrap();
        assert_eq!(
            permissions,
            ["read".to_string(), "write".to_string(), "other".to_string()]
                .iter()
                .cloned()
                .collect()
        );
    }

    #[tokio::test]
    async fn test_has_perm() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["read".to_string()]);

        let has_read_perm = backend.has_perm(&user, "read".to_string()).await.unwrap();
        assert!(has_read_perm);

        let has_delete_perm = backend.has_perm(&user, "delete".to_string()).await.unwrap();
        assert!(!has_delete_perm);
    }

    #[tokio::test]
    async fn test_has_multiple_perm() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["write".to_string(), "read".to_string()]);

        let has_read_and_write_perms = backend.has_perm(&user, "read".to_string()).await.unwrap()
            && backend.has_perm(&user, "write".to_string()).await.unwrap();
        assert!(has_read_and_write_perms);

        let has_read_and_delete_perms = backend.has_perm(&user, "read".to_string()).await.unwrap()
            && backend.has_perm(&user, "delete".to_string()).await.unwrap();
        assert!(!has_read_and_delete_perms);
    }

    #[tokio::test]
    async fn test_user_with_no_permissions() {
        let user = TestUser {
            id: 2,
            pw_hash: vec![5, 6, 7, 8],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec![]);

        let permissions = backend.get_user_permissions(&user).await.unwrap();
        assert!(permissions.is_empty());

        let permissions = backend.get_group_permissions(&user).await.unwrap();
        assert!(permissions.is_empty());

        let permissions = backend.get_all_permissions(&user).await.unwrap();
        assert!(permissions.is_empty());
    }

    #[tokio::test]
    async fn test_has_all_perm() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["write".to_string(), "read".to_string()]);
        let permissions = vec!["write".to_string(), "read".to_string()];

        let has_read_and_write_perms = backend.has_all_perm(&user, permissions).await.unwrap()
            && backend.has_perm(&user, "write".to_string()).await.unwrap();
        assert!(has_read_and_write_perms);
    }

    #[tokio::test]
    async fn test_user_without_all_perm() {
        let user = TestUser {
            id: 1,
            pw_hash: vec![1, 2, 3, 4],
        };
        let mut backend = TestBackend::new();
        backend.add_user(user.clone(), vec!["read".to_string()]);
        let permissions = vec!["write".to_string(), "read".to_string()];

        let has_read_and_write_perms = backend.has_all_perm(&user, permissions).await.unwrap()
            && backend.has_perm(&user, "write".to_string()).await.unwrap();
        assert!(!has_read_and_write_perms);
    }
}

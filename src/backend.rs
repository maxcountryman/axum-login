use std::{collections::HashSet, hash::Hash};

use async_trait::async_trait;
use http::Request;
use secrecy::SecretVec;
use serde::{Deserialize, Serialize};

pub type UserId<Backend> = <<Backend as AuthBackend>::User as AuthUser>::Id;

pub trait AuthUser: Clone + Send + Sync {
    type Id: Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>;

    fn id(&self) -> Self::Id;

    fn session_auth_hash(&self) -> Vec<u8>;
}

#[async_trait]
pub trait AuthBackend: Clone + Send + Sync {
    type User: AuthUser;
    type Credentials: Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error>;

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error>;
}

#[async_trait]
pub trait WithPermissions: Clone + Send + Sync
where
    Self: AuthBackend,
{
    type Permission: Hash + Eq + Clone + Send + Sync;

    async fn get_user_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    async fn get_group_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    async fn get_all_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let mut all_perms = HashSet::new();
        all_perms.extend(self.get_user_permissions(user).await?);
        all_perms.extend(self.get_group_permissions(user).await?);
        Ok(all_perms)
    }

    async fn has_perm(
        &self,
        user: &Self::User,
        perm: Self::Permission,
    ) -> Result<bool, Self::Error> {
        Ok(self.get_all_permissions(user).await?.contains(&perm))
    }
}

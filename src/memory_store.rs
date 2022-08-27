use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{user_store::UserStore, AuthUser};

/// An ephemeral store, useful for testing and demonstration purposes.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore<User> {
    inner: Arc<RwLock<HashMap<String, User>>>,
}

impl<User> MemoryStore<User> {
    pub fn new(inner: &Arc<RwLock<HashMap<String, User>>>) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

#[async_trait]
impl<User> UserStore for MemoryStore<User>
where
    User: AuthUser,
{
    type User = User;

    async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
        Ok(self.inner.read().await.get(user_id).cloned())
    }
}

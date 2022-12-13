//! An in-memory implementation of `UserStore`.

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
    /// Creates a new memory store.
    ///
    /// ```rust
    /// use std::{collections::HashMap, sync::Arc};
    ///
    /// use axum_login::memory_store::MemoryStore;
    /// use tokio::sync::RwLock;
    ///
    /// let inner = Arc::new(RwLock::new(HashMap::<String, ()>::new()));
    /// let memory_store = MemoryStore::new(&inner);
    /// ```
    pub fn new(inner: &Arc<RwLock<HashMap<String, User>>>) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

#[async_trait]
impl<User, Role> UserStore<Role> for MemoryStore<User>
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<Role>,
{
    type User = User;

    async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
        Ok(self.inner.read().await.get(user_id).cloned())
    }
}

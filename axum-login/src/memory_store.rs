//! An in-memory implementation of `UserStore`.

use std::{cmp::Eq, collections::HashMap, hash::Hash, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{user_store::UserStore, AuthUser};

/// An ephemeral store, useful for testing and demonstration purposes.
#[derive(Clone, Debug, Default)]
pub struct MemoryStore<UserId, User> {
    inner: Arc<RwLock<HashMap<UserId, User>>>,
}

impl<UserId, User> MemoryStore<UserId, User> {
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
    pub fn new(inner: &Arc<RwLock<HashMap<UserId, User>>>) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

#[async_trait]
impl<UserId, User, Role> UserStore<UserId, Role> for MemoryStore<UserId, User>
where
    UserId: Eq + Clone + Send + Sync + Hash + 'static,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role>,
{
    type User = User;

    async fn load_user(&self, user_id: &UserId) -> crate::Result<Option<Self::User>> {
        Ok(self.inner.read().await.get(user_id).cloned())
    }
}

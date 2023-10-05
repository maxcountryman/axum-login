use async_trait::async_trait;
use sqlx::{sqlite, FromRow, Sqlite, SqlitePool};

use crate::UserStore;

use super::DefaultQueryProvider;

pub struct SqliteQueryProvider;

impl DefaultQueryProvider for SqliteQueryProvider {
    fn default_query() -> String {
        "select * from users where id = ?".to_string()
    }
}

#[derive(Debug, Clone)]
pub struct SqliteUserStore {
    pool: SqlitePool,
    query: String,
}

impl SqliteUserStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            query: SqliteQueryProvider::default_query(),
        }
    }

    pub fn with_query(mut self, query: impl AsRef<str>) -> Self {
        let query = query.as_ref();
        self.query = query.to_string();
        self
    }
}

#[derive(thiserror::Error, Debug)]
pub enum SqlxStoreError {
    /// A variant to map `sqlx` errors.
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
impl<User, UserId> UserStore<User, UserId> for SqliteUserStore
where
    User: Send + Sync + Unpin + for<'r> FromRow<'r, sqlite::SqliteRow>,
    UserId: Sync + sqlx::Type<Sqlite> + for<'q> sqlx::Encode<'q, Sqlite>,
{
    type Error = SqlxStoreError;

    async fn load(&self, user_id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as(&self.query)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }
}

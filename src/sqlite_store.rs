use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;
use sqlx::{pool::PoolConnection, sqlite::SqliteRow, FromRow, Sqlite, SqlitePool};

use crate::{user_store::UserStore, AuthUser};

const TABLE_NAME_TEMPLATE: &str = "{{table_name}}";

#[derive(Clone, Debug)]
pub struct SqliteStore<User> {
    pool: SqlitePool,
    table_name: String,
    _user_type: PhantomData<User>,
}

impl<User> SqliteStore<User>
{
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool,
            table_name: "users".into(),
            _user_type: Default::default(),
        }
    }

    pub async fn new(database_url: &str) -> sqlx::Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        Ok(Self::from_pool(pool))
    }

    pub async fn new_with_table_name(database_url: &str, table_name: &str) -> sqlx::Result<Self> {
        Ok(Self::new(database_url).await?.with_table_name(table_name))
    }

    pub fn with_table_name(mut self, table_name: impl AsRef<str>) -> Self {
        let table_name = table_name.as_ref();
        self.table_name = table_name.to_string();
        self
    }
}

#[async_trait]
impl<User> UserStore for SqliteStore<User>
where
    User: AuthUser + Unpin + for<'r> FromRow<'r, SqliteRow>,
{
    type User = User;

    async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
        let query = format!("select * from {} where id = $1", TABLE_NAME_TEMPLATE);
        let query = query.replace(TABLE_NAME_TEMPLATE, &self.table_name);

        let mut connection = self.pool.acquire().await?;

        let user: Option<User> = sqlx::query_as(&query)
            .bind(&user_id)
            .fetch_optional(&mut connection)
            .await?;
        Ok(user)
    }
}

use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;
use sqlx::{pool::PoolConnection, postgres::PgRow, FromRow, PgPool, Postgres};

use crate::{user_store::UserStore, AuthUser};

#[derive(Clone, Debug)]
pub struct PostgresStore<User> {
    client: PgPool,
    table_name: String,
    _user_type: PhantomData<User>,
}

impl<User> PostgresStore<User>
where
    User: AuthUser,
{
    pub fn from_client(client: PgPool) -> Self {
        Self {
            client,
            table_name: "users".into(),
            _user_type: Default::default(),
        }
    }

    pub async fn new(database_url: &str) -> sqlx::Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self::from_client(pool))
    }

    pub async fn new_with_table_name(database_url: &str, table_name: &str) -> sqlx::Result<Self> {
        Ok(Self::new(database_url).await?.with_table_name(table_name))
    }

    pub fn with_table_name(mut self, table_name: impl AsRef<str>) -> Self {
        let table_name = table_name.as_ref();
        self.table_name = table_name.to_string();
        self
    }

    fn substitute_table_name(&self, query: &str) -> String {
        query.replace("{{USER_TABLE_NAME}}", &self.table_name)
    }

    async fn get_connection(&self) -> sqlx::Result<PoolConnection<Postgres>> {
        self.client.acquire().await
    }
}

#[async_trait]
impl<User> UserStore for PostgresStore<User>
where
    User: AuthUser + Unpin + for<'r> FromRow<'r, PgRow>,
{
    type User = User;

    async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
        let query = self.substitute_table_name("select * from {{USER_TABLE_NAME}} where id = $1");
        let mut connection = self.get_connection().await?;
        let user: Option<User> = sqlx::query_as(&query)
            .bind(&user_id)
            .fetch_optional(&mut connection)
            .await?;
        Ok(user)
    }
}

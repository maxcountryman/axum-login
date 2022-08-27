use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;
use sqlx::FromRow;
#[cfg(feature = "mssql")]
use sqlx::{mssql::MssqlRow, MssqlPool};
#[cfg(feature = "mysql")]
use sqlx::{mysql::MySqlRow, MySqlPool};
#[cfg(feature = "postgres")]
use sqlx::{postgres::PgRow, PgPool};
#[cfg(feature = "sqlite")]
use sqlx::{sqlite::SqliteRow, SqlitePool};

use crate::{user_store::UserStore, AuthUser};

const TABLE_NAME_TEMPLATE: &str = "{{table_name}}";

#[derive(Clone, Debug)]
pub struct SqlxStore<Pool, User> {
    pool: Pool,
    table_name: String,
    _user_type: PhantomData<User>,
}

impl<Pool, User> SqlxStore<Pool, User> {
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            table_name: "users".into(),
            _user_type: Default::default(),
        }
    }

    pub fn with_table_name(mut self, table_name: impl AsRef<str>) -> Self {
        let table_name = table_name.as_ref();
        self.table_name = table_name.to_string();
        self
    }
}

macro_rules! impl_user_store {
    ( $store:ident, $row:ident ) => {
        #[async_trait]
        impl<User> UserStore for $store<User>
        where
            User: AuthUser + Unpin + for<'r> FromRow<'r, $row>,
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
    };
}

/// A Mssql user store via sqlx.
#[cfg(feature = "mssql")]
pub type MssqlStore<User> = SqlxStore<MssqlPool, User>;

/// A MySql user store via sqlx.
#[cfg(feature = "mysql")]
pub type MySqlStore<User> = SqlxStore<MySqlPool, User>;

/// A Postgres user store via sqlx.
#[cfg(feature = "postgres")]
pub type PostgresStore<User> = SqlxStore<PgPool, User>;

/// A Sqlite user store via sqlx.
#[cfg(feature = "sqlite")]
pub type SqliteStore<User> = SqlxStore<SqlitePool, User>;

#[cfg(feature = "mssql")]
impl_user_store!(MssqlStore, MssqlRow);
#[cfg(feature = "mysql")]
impl_user_store!(MySqlStore, MySqlRow);
#[cfg(feature = "postgres")]
impl_user_store!(PostgresStore, PgRow);
#[cfg(feature = "sqlite")]
impl_user_store!(SqliteStore, SqliteRow);

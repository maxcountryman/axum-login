use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;
#[cfg(feature = "mssql")]
use sqlx::{mssql::MssqlRow, Mssql, MssqlPool};
#[cfg(feature = "mysql")]
use sqlx::{mysql::MySqlRow, MySql, MySqlPool};
#[cfg(feature = "postgres")]
use sqlx::{postgres::PgRow, PgPool, Postgres};
#[cfg(feature = "sqlite")]
use sqlx::{sqlite::SqliteRow, Sqlite, SqlitePool};
use sqlx::{Encode, FromRow, Type};

use crate::{user_store::UserStore, AuthUser};

pub trait DefaultQueryProvider: Clone {
    fn default_query() -> String;
}

#[derive(Clone)]
pub struct SqlxQueryProvider;

impl DefaultQueryProvider for SqlxQueryProvider {
    fn default_query() -> String {
        "SELECT * FROM users WHERE id = $1".to_string()
    }
}

#[derive(Clone)]
pub struct MySqlQueryProvider;

impl DefaultQueryProvider for MySqlQueryProvider {
    fn default_query() -> String {
        "SELECT * FROM users WHERE id = ?".to_string()
    }
}

/// A generic SQLx user store.
///
/// Concrete implementations are provided as well and should usually be used
/// unless generics are required by the application.
#[derive(Clone, Debug)]
pub struct SqlxStore<Pool, User, Role = (), QueryProvider: DefaultQueryProvider = SqlxQueryProvider>
{
    pool: Pool,
    query: String,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
    _default_query_provider_type: PhantomData<QueryProvider>,
}

impl<Pool, User, Role, QueryProvider> SqlxStore<Pool, User, Role, QueryProvider>
where
    QueryProvider: DefaultQueryProvider,
{
    /// Creates a new store with the provided pool.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            query: QueryProvider::default_query(),
            _user_type: Default::default(),
            _role_type: Default::default(),
            _default_query_provider_type: Default::default(),
        }
    }

    /// Sets the query that will be used to query the users table with
    /// `load_user`.
    pub fn with_query(mut self, query: impl AsRef<str>) -> Self {
        let query = query.as_ref();
        self.query = query.to_string();
        self
    }
}

macro_rules! impl_user_store {
    ( $db:ident, $store:ident, $row:ident ) => {
        #[async_trait]
        impl<UserId, User, Role> UserStore<UserId, Role> for $store<User, Role>
        where
            UserId: Sync + Type<$db> + for<'q> Encode<'q, $db>,
            Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
            User: AuthUser<UserId, Role> + Unpin + for<'r> FromRow<'r, $row>,
        {
            type User = User;

            type Error = sqlx::error::Error;

            async fn load_user(&self, user_id: &UserId) -> Result<Option<Self::User>, Self::Error> {
                let mut connection = self.pool.acquire().await?;

                let user: Option<User> = sqlx::query_as(&self.query)
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
pub type MssqlStore<User, Role = ()> = SqlxStore<MssqlPool, User, Role>;

/// A MySql user store via sqlx.
#[cfg(feature = "mysql")]
pub type MySqlStore<User, Role = ()> = SqlxStore<MySqlPool, User, Role, MySqlQueryProvider>;

/// A Postgres user store via sqlx.
#[cfg(feature = "postgres")]
pub type PostgresStore<User, Role = ()> = SqlxStore<PgPool, User, Role>;

/// A Sqlite user store via sqlx.
#[cfg(feature = "sqlite")]
pub type SqliteStore<User, Role = ()> = SqlxStore<SqlitePool, User, Role>;

#[cfg(feature = "mssql")]
impl_user_store!(Mssql, MssqlStore, MssqlRow);
#[cfg(feature = "mysql")]
impl_user_store!(MySql, MySqlStore, MySqlRow);
#[cfg(feature = "postgres")]
impl_user_store!(Postgres, PostgresStore, PgRow);
#[cfg(feature = "sqlite")]
impl_user_store!(Sqlite, SqliteStore, SqliteRow);

#[cfg(test)]
mod tests {
    use secrecy::SecretVec;
    use sqlx::SqlitePool;

    use crate::{
        sqlx_store::{DefaultQueryProvider, MySqlQueryProvider},
        AuthUser, SqliteStore,
    };

    #[derive(Debug, Default, Clone, sqlx::FromRow)]
    struct User {
        id: i64,
        password_hash: String,
    }

    impl AuthUser<i64> for User {
        fn get_id(&self) -> i64 {
            self.id
        }

        fn get_password_hash(&self) -> SecretVec<u8> {
            SecretVec::new(self.password_hash.clone().into())
        }
    }

    #[sqlx::test]
    async fn test_store_without_query_override_has_default_query(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool);
        assert_eq!(store.query, "SELECT * FROM users WHERE id = $1".to_string());
    }

    #[sqlx::test]
    async fn test_mysql_store_without_query_override_has_default_query() {
        let query: String = MySqlQueryProvider::default_query();
        assert_eq!(query, "SELECT * FROM users WHERE id = ?".to_string());
    }

    #[sqlx::test]
    async fn test_store_full_query_override(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool).with_query("select 1 from foo");
        assert_eq!(store.query, "select 1 from foo".to_string());
    }
}

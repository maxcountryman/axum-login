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

/// A generic SQLx user store.
///
/// Concrete implementations are provided as well and should usually be used
/// unless generics are required by the application.
#[derive(Clone, Debug)]
pub struct SqlxStore<Pool, User, Role = ()> {
    pool: Pool,
    query: String,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

impl<Pool, User, Role> SqlxStore<Pool, User, Role> {
    /// Creates a new store with the provided pool.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            query: "SELECT * FROM users WHERE id = $1".to_string(),
            _user_type: Default::default(),
            _role_type: Default::default(),
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
    ( $store:ident, $row:ident ) => {
        #[async_trait]
        impl<User, Role> UserStore<Role> for $store<User, Role>
        where
            Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
            User: AuthUser<Role> + Unpin + for<'r> FromRow<'r, $row>,
        {
            type User = User;

            async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
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
pub type MySqlStore<User, Role = ()> = SqlxStore<MySqlPool, User, Role>;

/// A Postgres user store via sqlx.
#[cfg(feature = "postgres")]
pub type PostgresStore<User, Role = ()> = SqlxStore<PgPool, User, Role>;

/// A Sqlite user store via sqlx.
#[cfg(feature = "sqlite")]
pub type SqliteStore<User, Role = ()> = SqlxStore<SqlitePool, User, Role>;

#[cfg(feature = "mssql")]
impl_user_store!(MssqlStore, MssqlRow);
#[cfg(feature = "mysql")]
impl_user_store!(MySqlStore, MySqlRow);
#[cfg(feature = "postgres")]
impl_user_store!(PostgresStore, PgRow);
#[cfg(feature = "sqlite")]
impl_user_store!(SqliteStore, SqliteRow);

#[cfg(test)]
mod tests {
    //todo: integration tests - docker-compose for non-memory db servers?

    use secrecy::SecretVec;
    use sqlx::SqlitePool;

    use crate::{AuthUser, SqliteStore};

    #[derive(Debug, Default, Clone, sqlx::FromRow)]
    struct User {
        id: i64,
        password_hash: String,
    }

    impl AuthUser for User {
        fn get_id(&self) -> String {
            format!("{}", self.id)
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
    async fn test_store_full_query_override(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool).with_query("select 1 from foo");
        assert_eq!(store.query, "select 1 from foo".to_string());
    }
}

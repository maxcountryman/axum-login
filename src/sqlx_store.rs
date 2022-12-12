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
const COLUMN_NAME_TEMPLATE: &str = "{{column_name}}";

/// A generic SQLx user store.
///
/// Concrete implementations are provided as well and should usually be used
/// unless generics are required by the application.
#[derive(Clone, Debug)]
pub struct SqlxStore<Pool, User, Role = ()> {
    pool: Pool,
    table_name: String,
    column_name: String,
    query: Option<String>,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

impl<Pool, User, Role> SqlxStore<Pool, User, Role> {
    /// Creates a new store with the provided pool.
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            table_name: "users".into(),
            column_name: "id".into(),
            query: None,
            _user_type: Default::default(),
            _role_type: Default::default(),
        }
    }

    /// Sets the name of the table which will be queried when calling
    /// `load_user`.
    pub fn with_table_name(mut self, table_name: impl AsRef<str>) -> Self {
        let table_name = table_name.as_ref();
        self.table_name = table_name.to_string();
        self
    }

    /// Sets the name of the column that will be used to query the user with
    /// `load_user`.
    pub fn with_column_name(mut self, column_name: impl AsRef<str>) -> Self {
        let column_name = column_name.as_ref();
        self.column_name = column_name.to_string();
        self
    }

    /// Sets the query that will be used to query the user with `load_user`.
    /// Note: It doesn't really make sense to use `with_query`
    /// and `with_table_name` / `with_column_name` pair at the same time.
    /// The query, if set, will be used instead of the table name and column name.
    pub fn with_query(mut self, query: impl AsRef<str>) -> Self {
        let query = query.as_ref();
        self.query = Some(query.to_string());
        self
    }

    async fn build_db_query(&self) -> String {
        if let Some(query) = self.query.clone() {
            query
        } else {
            let mut query = format!(
                "SELECT * FROM {} WHERE {} = $1",
                TABLE_NAME_TEMPLATE, COLUMN_NAME_TEMPLATE
            );
            query = query.replace(TABLE_NAME_TEMPLATE, &self.table_name);
            query = query.replace(COLUMN_NAME_TEMPLATE, &self.column_name);
            query
        }
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
                let query = self.build_db_query().await;
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
    use crate::{AuthUser, SqliteStore, SqlxStore};

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
    async fn test_store_table_override(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool).with_table_name("foo");
        assert_eq!(store.table_name, "foo");
    }

    #[sqlx::test]
    async fn test_store_column_override(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool).with_column_name("foo");
        assert_eq!(store.column_name, "foo");
    }

    #[sqlx::test]
    async fn test_store_without_query_override_has_query_none(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool);
        assert_eq!(store.query, None);
    }

    #[sqlx::test]
    async fn test_store_full_query_override(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool).with_query("select 1 from foo");
        assert_eq!(store.query, Some("select 1 from foo".to_string()));
    }

    #[sqlx::test]
    async fn test_store_query_builder_respects_explicit_query(pool: SqlitePool) {
        let expected_q = "SELECT 'something' FROM certainly_changed_table WHERE certainly_changed_column = $1";
        let store = SqliteStore::<User>::new(pool).with_query(expected_q);
        assert_eq!(store.build_db_query().await, expected_q);
    }

    #[sqlx::test]
    async fn test_store_query_builder_respects_explicit_table_and_column_name(pool: SqlitePool) {
        let expected_q = "SELECT * FROM certainly_changed_table WHERE certainly_changed_column = $1";
        let table = "certainly_changed_table";
        let column = "certainly_changed_column";

        let store = SqliteStore::<User>::new(pool)
            .with_table_name(table)
            .with_column_name(column);
        assert_eq!(store.build_db_query().await, expected_q);
    }
}

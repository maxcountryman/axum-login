use std::{error::Error, fmt::Display, marker::PhantomData};

use async_trait::async_trait;
use axum_login::{axum_sessions::async_session, AuthUser, UserStore};
use libsql_client::{args, Row, Statement};

#[derive(Debug)]
pub enum Errors {
    DbExecutionError(async_session::Error),
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Errors::DbExecutionError(e) => write!(f, "DbExecutionError: {}", e),
        }
    }
}
impl Error for Errors {}

unsafe impl Send for Errors {}

/// A store to support rusqlite as the underlying database crate.
#[derive(Clone, Debug)]
pub struct LibsqlStore<User, UserMapper: LibsqlUserMapper<User = User>, Role = ()> {
    client: &'static libsql_client::Client,
    query: String,
    _user_mapper: PhantomData<UserMapper>,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

/// A mapper from a libsql row to a concrete user-defined `User` struct.
pub trait LibsqlUserMapper: Clone + Send + Sync + 'static {
    type User;

    fn map(row: &Row) -> Result<Self::User, Errors>;
}

impl<User, UserMapper, Role> LibsqlStore<User, UserMapper, Role>
where
    UserMapper: LibsqlUserMapper<User = User>,
{
    /// Creates a new store with the provided connection.
    pub fn new(client: &'static libsql_client::Client) -> Self {
        Self {
            client,
            query: "SELECT * FROM users WHERE id = $1".to_string(),
            _user_mapper: Default::default(),
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

#[async_trait]
impl<UserId, User, UserMapper, Role> UserStore<UserId, Role> for LibsqlStore<User, UserMapper, Role>
where
    UserId: Send + Sync + Clone + 'static + Into<libsql_client::Value>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role> + Unpin,
    UserMapper: LibsqlUserMapper<User = User>,
{
    type User = User;
    type Error = Errors;

    async fn load_user(&self, user_id: &UserId) -> Result<Option<Self::User>, Errors> {
        let stmt =
            Statement::with_args("SELECT * FROM users WHERE id = $1", args!(user_id.clone()));
        self.client
            .execute(stmt)
            .await
            // .map_err(|e| eyre::eyre!("failed to execute query: {}", e))
            .map_err(Errors::DbExecutionError)
            .and_then(|res| match res.rows.first() {
                Some(row) => UserMapper::map(&row).map(Some),
                None => Ok(None),
            })
    }
}

#[cfg(test)]
mod tests {
    use libsql_client::{Client, Row, Statement, args};
    use once_cell::sync::Lazy;
    use secrecy::SecretVec;

    use crate::Errors;

    use super::{LibsqlStore, LibsqlUserMapper};
    use axum_login::{secrecy, AuthUser, UserStore};

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct User {
        id: String,
        password_hash: String,
    }

    impl AuthUser<String> for User {
        fn get_id(&self) -> String {
            self.id.clone()
        }

        fn get_password_hash(&self) -> SecretVec<u8> {
            SecretVec::new(self.password_hash.clone().into())
        }
    }

    #[derive(Debug, Clone)]
    struct MyUserMapper;

    impl LibsqlUserMapper for MyUserMapper {
        type User = User;

        fn map(row: &Row) -> Result<Self::User, Errors> {
            Ok(User {
                id: row.try_get(0).map(|v: i32| v.to_string()).unwrap(),
                password_hash: row.try_get(1).map(|v: &str| v.to_string()).unwrap(),
            })
        }
    }

    const fn new_in_memory_connection() -> Lazy<Client> {
        Lazy::new(|| {
            libsql_client::Client::Local(libsql_client::local::Client::in_memory().unwrap())
        })
    }

    #[tokio::test]
    async fn test_store() {
        static CONN: Lazy<Client> = new_in_memory_connection();
        let store: LibsqlStore<User, MyUserMapper> = LibsqlStore::<User, MyUserMapper>::new(&CONN);

        CONN.execute("CREATE TABLE users(id NUMBER, password_hash TEXT);")
            .await
            .unwrap();

        let insert = Statement::with_args("INSERT INTO users VALUES ($1, $2);", args!(1, "test"));
        CONN.execute(insert)
            .await
            .unwrap();

        assert_eq!(store.query, "SELECT * FROM users WHERE id = $1".to_string());

        let user = store.load_user(&1.to_string()).await.unwrap().unwrap();
        assert_eq!(
            User {
                id: 1.to_string(),
                password_hash: "test".to_string()
            },
            user
        )
    }

    #[tokio::test]
    async fn test_store_without_query_override_has_default_query() {
        static CONN: Lazy<Client> = new_in_memory_connection();
        let store = LibsqlStore::<User, MyUserMapper>::new(&CONN);
        assert_eq!(
            store.query,
            "SELECT * FROM users WHERE id = $1".to_string()
        );
    }

    #[tokio::test]
    async fn test_store_full_query_override() {
        static CONN: Lazy<Client> = new_in_memory_connection();
        let store = LibsqlStore::<User, MyUserMapper>::new(&CONN).with_query("select 1 from foo");
        assert_eq!(store.query, "select 1 from foo".to_string());
    }
}

use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;
use rusqlite::{named_params, OptionalExtension, Row, ToSql};
use tokio_rusqlite::Connection;

use crate::{user_store::UserStore, AuthUser};

/// A mapper from a rusqlite row to a concrete user-defined `User` struct.
pub trait RusqliteUserMapper: Clone + Send + Sync + 'static {
    type User;

    fn map(row: &Row<'_>) -> Result<Self::User, rusqlite::Error>;
}

/// A store to support rusqlite as the underlying database crate.
#[derive(Clone, Debug)]
pub struct RusqliteStore<User, UserMapper: RusqliteUserMapper<User = User>, Role = ()> {
    connection: Connection,
    query: String,
    _user_mapper: PhantomData<UserMapper>,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

impl<User, UserMapper, Role> RusqliteStore<User, UserMapper, Role>
where
    UserMapper: RusqliteUserMapper<User = User>,
{
    /// Creates a new store with the provided connection.
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            query: "SELECT * FROM users WHERE id = :id".to_string(),
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
impl<UserId, User, UserMapper, Role> UserStore<UserId, Role>
    for RusqliteStore<User, UserMapper, Role>
where
    UserId: Send + Sync + ToSql + Clone + 'static,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role> + Unpin,
    UserMapper: RusqliteUserMapper<User = User>,
{
    type User = User;
    type Error = rusqlite::Error;

    async fn load_user(&self, user_id: &UserId) -> Result<Option<Self::User>, Self::Error> {
        let id = user_id.clone();
        let query = self.query.clone();
        self.connection
            .call(move |conn| {
                conn.query_row(&query, named_params! { ":id": id }, |row: &Row| {
                    let user: Result<Self::User, rusqlite::Error> = UserMapper::map(row);
                    user
                })
                .optional()
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretVec;
    use tokio_rusqlite::Connection;

    use super::RusqliteUserMapper;
    use crate::{user_store::UserStore, AuthUser, RusqliteStore};

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
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

    #[derive(Debug, Clone)]
    struct MyUserMapper;

    impl RusqliteUserMapper for MyUserMapper {
        type User = User;

        fn map(row: &rusqlite::Row<'_>) -> Result<Self::User, rusqlite::Error> {
            Ok(User {
                id: row.get(0)?,
                password_hash: row.get(1)?,
            })
        }
    }

    #[tokio::test]
    async fn test_store() {
        let conn = Connection::open_in_memory().await.unwrap();
        let conn2 = conn.clone();
        let store = RusqliteStore::<User, MyUserMapper>::new(conn);

        conn2
            .call(|conn| conn.execute("CREATE TABLE users(id NUMBER, password_hash TEXT);", []))
            .await
            .unwrap();

        conn2
            .call(|conn| conn.execute("INSERT INTO users VALUES (1, 'test');", []))
            .await
            .unwrap();

        assert_eq!(
            store.query,
            "SELECT * FROM users WHERE id = :id".to_string()
        );

        let user = store.load_user(&1).await.unwrap().unwrap();
        assert_eq!(
            User {
                id: 1,
                password_hash: "test".to_string()
            },
            user
        )
    }

    #[tokio::test]
    async fn test_store_without_query_override_has_default_query() {
        let conn = Connection::open_in_memory().await.unwrap();
        let store = RusqliteStore::<User, MyUserMapper>::new(conn);
        assert_eq!(
            store.query,
            "SELECT * FROM users WHERE id = :id".to_string()
        );
    }

    #[tokio::test]
    async fn test_store_full_query_override() {
        let conn = Connection::open_in_memory().await.unwrap();
        let store = RusqliteStore::<User, MyUserMapper>::new(conn).with_query("select 1 from foo");
        assert_eq!(store.query, "select 1 from foo".to_string());
    }
}

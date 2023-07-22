use std::marker::PhantomData;

use async_trait::async_trait;
use axum_login::{AuthUser, UserStore};
pub use errors::Errors;
use libsql_client::{args, Row, Statement};
mod errors;

/// A store to support rusqlite as the underlying database crate.
#[derive(Clone, Debug)]
pub struct LibsqlStore<User, UserMapper: LibsqlUserMapper<User = User>, Role = ()> {
    client: &'static libsql_client::Client,
    query: String,
    _user_mapper: PhantomData<UserMapper>,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

/// A mapper from a libsql_client::Row to a concrete user-defined `User` struct.
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
                Some(row) => UserMapper::map(row).map(Some),
                None => Ok(None),
            })
    }
}

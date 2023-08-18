use std::marker::{PhantomData, Unpin};

pub trait DefaultQueryProvider: Clone {
    fn default_query() -> String;
}
#[derive(Clone)]
pub struct DieselQueryProvider;
impl DefaultQueryProvider for DieselQueryProvider {
    fn default_query() -> String {
        "SELECT * FROM users WHERE id = $1".to_string()
    }
}

#[derive(Clone, Debug)]
pub struct DieselStore<Pool, User, Role = (), QueryProvider: DefaultQueryProvider = DieselQueryProvider>
{
    pool: Pool,
    query: String,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
    _default_query_provider_type: PhantomData<QueryProvider>,
}

impl<Pool, User, Role, QueryProvider> DieselStore<Pool, User, Role, QueryProvider>
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
#[cfg(feature = "diesel_sqlite")]
pub type SqliteStore<User, Role = ()> = DieselStore<deadpool_diesel::sqlite::Pool, User, Role>;
/*
#[cfg(feature = "diesel_sqlite")]
impl_user_store!(Sqlite, SqliteStore, SqliteRow);
*/

use crate::{user_store::UserStore, AuthUser};
use async_trait::async_trait;
use diesel::RunQueryDsl;

#[async_trait]
impl<UserId, User, Role> UserStore<UserId, Role> for SqliteStore<User, Role>
where
    UserId: Sync + diesel::sql_types::SingleValue,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role> + Unpin + diesel::Queryable<User, diesel::sqlite::Sqlite>,
{
    type User = User;

    type Error = deadpool_diesel::PoolError;

    async fn load_user(&self, user_id: &UserId) -> Result<Option<Self::User>, Self::Error> {
        let mut connection = self.pool.get().await?;
        let query = self.query;
        let user : Option<User> = connection.interact(|conn| {
            let query = diesel::sql_query(query);
            query.get_result::<User>(conn).ok()
        }).await.ok().flatten();

        Ok(user)
    }
}

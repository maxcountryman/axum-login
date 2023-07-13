//! A MongoDB implementation of `UserStore`

use std::marker::PhantomData;

use mongodb::bson::Bson;
use serde::de::DeserializeOwned;

use crate::{AuthUser, UserStore};

pub trait DefaultQueryProvider<T = mongodb::bson::oid::ObjectId>: Clone {
    fn field_name() -> String;
}

#[derive(Clone)]
pub struct MongoDBQueryProvider;

impl DefaultQueryProvider for MongoDBQueryProvider {
    fn field_name() -> String {
        "_id".to_string()
    }
}

/// MongoDB store implementation
#[derive(Clone, Debug)]
pub struct MongoDbStore<User, Role = (), QueryProvider: DefaultQueryProvider = MongoDBQueryProvider>
{
    collection: mongodb::Collection<User>,
    field_name: String,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
    _default_query_provider_type: PhantomData<QueryProvider>,
}

impl<User, Role, QueryProvider> MongoDbStore<User, Role, QueryProvider>
where
    QueryProvider: DefaultQueryProvider,
{
    /// Creates a new store with the provided collection.
    pub fn new(collection: mongodb::Collection<User>) -> Self {
        Self {
            collection,
            field_name: QueryProvider::field_name(),
            _user_type: Default::default(),
            _role_type: Default::default(),
            _default_query_provider_type: Default::default(),
        }
    }

    /// Sets the field name that will be used to query the users collection with
    pub fn with_field_name(mut self, field_name: impl Into<String>) -> Self {
        self.field_name = field_name.into();

        self
    }
}

#[async_trait::async_trait]
impl<UserId, User, Role> UserStore<UserId, Role> for MongoDbStore<User, Role>
where
    UserId: Into<Bson> + Clone + Send + Sync + 'static,
    User: AuthUser<UserId, Role> + DeserializeOwned + Unpin + Send + Sync + 'static,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    type User = User;
    type Error = mongodb::error::Error;

    async fn load_user(&self, id: &UserId) -> Result<Option<Self::User>, Self::Error> {
        let id = id.clone();

        let mut filter = mongodb::bson::Document::new();
        filter.insert(&self.field_name, &id);

        let user = self.collection.find_one(filter, None).await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mongodb::bson::{doc, oid::ObjectId};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct TestUser {
        id: ObjectId,
        username: String,
        password: String,
        role: String,
    }

    impl AuthUser<ObjectId> for TestUser {
        fn get_id(&self) -> ObjectId {
            self.id.clone()
        }

        fn get_password_hash(&self) -> secrecy::SecretVec<u8> {
            secrecy::SecretVec::new(self.password.clone().into())
        }
    }

    fn get_mongodb_uri() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "mongodb://localhost:27017".to_string())
    }

    #[tokio::test]
    async fn test_store_without_field_name_override_has_default_field_name() {
        let client = {
            let uri = get_mongodb_uri();
            let client = mongodb::Client::with_uri_str(&uri).await.unwrap();

            client
        };

        let db = client.database("axum_login_test");

        let collection = db.collection::<TestUser>("users");

        let store = MongoDbStore::<TestUser>::new(collection.clone());

        assert_eq!(store.field_name, "_id");
    }

    #[tokio::test]
    async fn test_store_without_field_name_override() {
        let client = {
            let uri = get_mongodb_uri();
            let client = mongodb::Client::with_uri_str(&uri).await.unwrap();

            client
        };

        let db = client.database("axum_login_test");

        let collection = db.collection::<TestUser>("users");

        let store = MongoDbStore::<TestUser>::new(collection.clone()).with_field_name("email");

        assert_eq!(store.field_name, "email");
    }
}

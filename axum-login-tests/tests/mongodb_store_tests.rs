use axum_login::{secrecy, AuthUser};
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct TestUser {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    username: String,
    password: String,
    role: String,
}

impl AuthUser<ObjectId> for TestUser {
    fn get_id(&self) -> ObjectId {
        self.id.clone().unwrap()
    }

    fn get_password_hash(&self) -> secrecy::SecretVec<u8> {
        secrecy::SecretVec::new(self.password.clone().into())
    }
}

#[cfg(feature = "mongodb")]
mod mongodb_tests {
    use axum_login::{MongoDbStore, UserStore};

    use super::*;

    fn get_mongodb_uri() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "mongodb://localhost:27017".to_string())
    }

    #[tokio::test]
    async fn test_load_user() {
        let client = {
            let uri = get_mongodb_uri();
            let client = mongodb::Client::with_uri_str(&uri).await.unwrap();

            client
        };

        let db = client.database("axum_login_test");

        let collection = db.collection::<TestUser>("users");

        let store = MongoDbStore::<TestUser>::new(collection.clone());

        let user = TestUser {
            id: Some(ObjectId::new()),
            username: "test".to_string(),
            password: "test".to_string(),
            role: "test".to_string(),
        };

        let res = collection.insert_one(&user, None).await.unwrap();

        let id = res.inserted_id.as_object_id().unwrap();

        let loaded_user = store.load_user(&id).await.unwrap().unwrap();

        assert_eq!(user, loaded_user);
    }
}

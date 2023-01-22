use std::marker::{PhantomData, Unpin};

use async_trait::async_trait;

#[cfg(feature = "redis")]
use redis::{Client, Connection, Commands, FromRedisValue};

use crate::{user_store::UserStore, AuthUser};

/// Redis user store.
#[derive(Clone, Debug)]
pub struct RedisStore<User, Role = ()> {
    client: Client,
    _user_type: PhantomData<User>,
    _role_type: PhantomData<Role>,
}

impl<User, Role> RedisStore<User, Role> {
    /// Creates a new store with the provided client.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            _user_type: Default::default(),
            _role_type: Default::default(),
        }
    }
}

#[async_trait]
impl<User, Role> UserStore<Role> for RedisStore<User, Role>
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    User: AuthUser<Role> + Unpin + FromRedisValue,
{
    type User = User;

    /// user_id is the unique Redis key under which the user data is stored.
    ///
    /// Note: This key must be returned by your implementation of `get_id(...)` for the
    /// `AuthUser`-trait.
    async fn load_user(&self, user_id: &str) -> crate::Result<Option<Self::User>> {
        let mut con: Connection = self.client.get_connection()?;
        let user: Option<User> = con.get(user_id).ok();
        Ok(user)
    }
}


#[cfg(test)]
mod tests {
    use secrecy::SecretVec;
    use redis::{FromRedisValue, from_redis_value};
    use serde::{Serialize, Deserialize};
    use serde_json;
    use crate::AuthUser;

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    struct User {
        id: String,
        name: String,
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

    // FromRedisValue has to be implemented for User
    impl FromRedisValue for User {
        fn from_redis_value(v: &redis::Value) -> redis::RedisResult<Self> {
            let user: String = from_redis_value(v)?;
            let user: User = serde_json::from_str(user.as_str())?;
            Ok(user)
        }
    }
}

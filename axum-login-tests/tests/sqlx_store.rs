use sqlx::FromRow;

use axum_login::AuthUser;
use axum_login::secrecy::SecretVec;

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

macro_rules! test_db_backend {
    ($name:ident, $store:ty, $pool:ty) => {

        #[sqlx::test]
        async fn $name(pool: $pool) {


            let store = <$store>::<User>::new(pool);

            let user = store.load_user("1").await.unwrap().unwrap();

            assert_eq!(user.get_id(), "1");
            assert_eq!(user.get_name(), "Rusty");
        }
    };
}

#[cfg(feature = "postgres")]
mod tests {
    use sqlx::PgPool;
    use axum_login::PostgresStore;

    test_db_backend!(test_pg_store, PostgresStore, PgPool);
}


#[cfg(feature = "mysql")]
mod tests {
    use sqlx::MySqlPool;
    use axum_login::MySqlStore;

    test_db_backend!(test_sqlx_store, MySqlStore, MySqlPool);
}

use sqlx;

use axum_login::{AuthUser, secrecy::SecretVec};

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

// todo: revisit the macro once you know what you're doing
macro_rules! test_db_backend {
    ($test_name:ident, $store:ty, $pool:ty) => {
        use $crate::User;
        #[sqlx::test]
        async fn $test_name(pool: $pool) {
            let store = $store::<User>::new(pool);

            let user = store.load_user("1").await.unwrap().unwrap();

            assert_eq!(user.get_id(), "1");
        }
    };
}

#[cfg(feature = "sqlite")]
test_db_backend!(test_sqlite, axum_login::SqliteStore, sqlx::SqlitePool);

#[cfg(feature = "postgres")]
test_db_backend!(test_postgres, axum_login::PostgresStore, sqlx::PgPool);

#[cfg(feature = "mysql")]
test_db_backend!(test_mysql, axum_login::MySqlStore, sqlx::MySqlPool);

//
// #[cfg(feature = "postgres")]
// mod tests_pg {
//     use sqlx::PgPool;
//
//     use axum_login::{AuthUser, PostgresStore, UserStore};
//
//     use super::User;
//
//     #[sqlx::test]
//     async fn test_pg(pool: PgPool) {
//         let store = PostgresStore::<User>::new(pool);
//
//         let user = store.load_user("1").await.unwrap().unwrap();
//
//         assert_eq!(user.get_id(), "1");
//     }
// }
//
// #[cfg(feature = "mysql")]
// mod tests_mysql {
//     use sqlx::MySqlPool;
//
//     use axum_login::AuthUser;
//     use axum_login::MySqlStore;
//     use axum_login::UserStore;
//
//     use super::User;
//
//     #[sqlx::test]
//     async fn test_mysql(pool: MySqlPool) {
//         let store = MySqlStore::<User>::new(pool);
//
//         let user = store.load_user("1").await.unwrap().unwrap();
//
//         assert_eq!(user.get_id(), "1");
//     }
// }

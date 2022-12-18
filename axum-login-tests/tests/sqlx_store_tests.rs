use sqlx;

use axum_login::secrecy::SecretVec;
use axum_login::AuthUser;

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

#[cfg(feature = "postgres")]
mod tests_pg {
    use sqlx::PgPool;

    use axum_login::{AuthUser, PostgresStore, UserStore};

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: PgPool) {
        let store = PostgresStore::<User>::new(pool);

        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

#[cfg(feature = "mysql")]
mod tests_mysql {
    use sqlx::MySqlPool;

    use axum_login::AuthUser;
    use axum_login::MySqlStore;
    use axum_login::UserStore;

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: MySqlPool) {
        let store = MySqlStore::<User>::new(pool);

        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

#[cfg(feature = "sqlite")]
mod tests_sqlite {
    use sqlx::SqlitePool;

    use axum_login::UserStore;
    use axum_login::{AuthUser, SqliteStore};

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool);

        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

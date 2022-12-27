use axum_login::{secrecy::SecretVec, AuthUser};

#[derive(Debug, Default, Clone, sqlx::FromRow)]
struct User {
    id: i32,
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
    use axum_login::{AuthUser, PostgresStore, UserStore};
    use sqlx::PgPool;

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: PgPool) {
        // custom query because the default one assumes text-ish id column
        let store = PostgresStore::<User>::new(pool)
            .with_query("SELECT * FROM users WHERE id = $1::numeric");
        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

#[cfg(feature = "mysql")]
mod tests_mysql {
    use axum_login::{AuthUser, MySqlStore, UserStore};
    use sqlx::MySqlPool;

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: MySqlPool) {
        // custom query because of the way mysql binds are done
        let store = MySqlStore::<User>::new(pool).with_query("SELECT * FROM users WHERE id = ?");

        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

#[cfg(feature = "sqlite")]
mod tests_sqlite {
    use axum_login::{AuthUser, SqliteStore, UserStore};
    use sqlx::SqlitePool;

    use super::User;

    #[sqlx::test(fixtures("users"))]
    async fn test_load_user(pool: SqlitePool) {
        let store = SqliteStore::<User>::new(pool);

        let user = store.load_user("1").await.unwrap().unwrap();

        assert_eq!(user.get_id(), "1");
    }
}

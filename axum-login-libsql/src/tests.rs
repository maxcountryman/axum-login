use axum_login::{secrecy, AuthUser, UserStore};
use libsql_client::{args, Client, Row, Statement};
use once_cell::sync::Lazy;
use secrecy::SecretVec;

use crate::{LibsqlStore, LibsqlUserMapper};
use crate::Errors;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct User {
    id: String,
    password_hash: String,
}

impl AuthUser<String> for User {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }
}

#[derive(Debug, Clone)]
struct MyUserMapper;

impl LibsqlUserMapper for MyUserMapper {
    type User = User;

    fn map(row: &Row) -> Result<Self::User, Errors> {
        Ok(User {
            id: row.try_get(0).map(|v: i32| v.to_string()).unwrap(),
            password_hash: row.try_get(1).map(|v: &str| v.to_string()).unwrap(),
        })
    }
}

const fn new_in_memory_connection() -> Lazy<Client> {
    Lazy::new(|| {
        libsql_client::Client::Local(libsql_client::local::Client::in_memory().unwrap())
    })
}

#[tokio::test]
async fn test_store() {
    static CONN: Lazy<Client> = new_in_memory_connection();
    let store: LibsqlStore<User, MyUserMapper> = LibsqlStore::<User, MyUserMapper>::new(&CONN);

    CONN.execute("CREATE TABLE users(id NUMBER, password_hash TEXT);")
        .await
        .unwrap();

    let insert = Statement::with_args("INSERT INTO users VALUES ($1, $2);", args!(1, "test"));
    CONN.execute(insert).await.unwrap();

    assert_eq!(store.query, "SELECT * FROM users WHERE id = $1".to_string());

    let user = store.load_user(&1.to_string()).await.unwrap().unwrap();
    assert_eq!(
        User {
            id: 1.to_string(),
            password_hash: "test".to_string()
        },
        user
    )
}

#[tokio::test]
async fn test_store_without_query_override_has_default_query() {
    static CONN: Lazy<Client> = new_in_memory_connection();
    let store = LibsqlStore::<User, MyUserMapper>::new(&CONN);
    assert_eq!(store.query, "SELECT * FROM users WHERE id = $1".to_string());
}

#[tokio::test]
async fn test_store_full_query_override() {
    static CONN: Lazy<Client> = new_in_memory_connection();
    let store = LibsqlStore::<User, MyUserMapper>::new(&CONN).with_query("select 1 from foo");
    assert_eq!(store.query, "select 1 from foo".to_string());
}
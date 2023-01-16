<h1 align="center">
axum-login
</h1>

<p align="center">
🪪 Session-based user authentication for Axum.
</p>

<div align="center">
<a href="https://crates.io/crates/axum-login">
<img src="https://img.shields.io/crates/v/axum-login.svg" />
</a>
<a href="https://docs.rs/axum-login">
<img src="https://docs.rs/axum-login/badge.svg" />
</a>
<a href="https://github.com/maxcountryman/axum-login/actions/workflows/rust.yml">
<img src="https://github.com/maxcountryman/axum-login/actions/workflows/rust.yml/badge.svg" />
</a>
<a href='https://coveralls.io/github/maxcountryman/axum-login?branch=main'>
<img src='https://coveralls.io/repos/github/maxcountryman/axum-login/badge.svg?branch=main' alt='Coverage Status' />
</a>
</div>

## 🎨 Overview

`axum-login` is a Tower middleware providing session-based user authentication for `axum` applications.

- Decouples user storage from authentication
- Supports arbitrary user types and arbitrary storage backends
- Provides methods for: logging in, logging out, and accessing current user
- Optional role-based access controls via an arbitrary role type
- Wraps `axum-sessions` to provide flexible sessions
- Leverages `tower_http::auth::RequireAuthorizationLayer` to protect routes

> **Note** `axum-login` implements a fundamental pattern for user authentication, however some features may be missing. Folks are encouraged to make suggestions for extensions to the library.

## 📦 Install

To use the crate in your project, add the following to your `Cargo.toml` file:

```toml
[dependencies]
axum-login = "0.4.1"
```

## 🤸 Usage

`axum` applications can use the middleware via the auth layer.

### `axum` Example

```rust
use axum::{response::IntoResponse, routing::get, Extension, Router};
use axum_login::{
    axum_sessions::{async_session::MemoryStore, SessionLayer},
    secrecy::SecretVec,
    AuthLayer, AuthUser, RequireAuthorizationLayer, SqliteStore,
};
use rand::Rng;
use sqlx::sqlite::SqlitePoolOptions;

#[derive(Debug, Default, Clone, sqlx::FromRow)]
struct User {
    id: i64,
    password_hash: String,
    name: String,
}

impl AuthUser<i64> for User {
    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }
}

type AuthContext = axum_login::extractors::AuthContext<i64, User, SqliteStore<User>>;

#[tokio::main]
async fn main() {
    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = MemoryStore::new();
    let session_layer = SessionLayer::new(session_store, &secret).with_secure(false);

    let pool = SqlitePoolOptions::new()
        .connect("sqlite/user_store.db")
        .await
        .unwrap();

    let user_store = SqliteStore::<User>::new(pool);
    let auth_layer = AuthLayer::new(user_store, &secret);

    async fn login_handler(mut auth: AuthContext) {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite/user_store.db")
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let user: User = sqlx::query_as("select * from users where id = 1")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        auth.login(&user).await.unwrap();
    }

    async fn logout_handler(mut auth: AuthContext) {
        dbg!("Logging out user: {}", &auth.current_user);
        auth.logout().await;
    }

    async fn protected_handler(Extension(user): Extension<User>) -> impl IntoResponse {
        format!("Logged in as: {}", user.name)
    }

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
        .route("/login", get(login_handler))
        .route("/logout", get(logout_handler))
        .layer(auth_layer)
        .layer(session_layer);

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

You can find this [example][sqlite-example] as well as other example projects in the [example directory][examples].

See the [crate documentation][docs] for more usage information.

[sqlite-example]: https://github.com/maxcountryman/axum-login/tree/main/examples/sqlite
[examples]: https://github.com/maxcountryman/axum-login/tree/main/examples
[docs]: https://docs.rs/axum-login

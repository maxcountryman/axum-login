<h1 align="center">
    axum-login
</h1>

<p align="center">
    🪪 User identification, authentication, and authorization for Axum.
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
    <a href="https://codecov.io/gh/maxcountryman/axum-login" > 
        <img src="https://codecov.io/gh/maxcountryman/axum-login/graph/badge.svg?token=4WKTLPEGJC"/> 
    </a>
</div>

## 🎨 Overview

This crate provides user identification, authentication, and authorization
as a `tower` middleware for `axum`.

It offers:

- **User Identification, Authentication, and Authorization**: Leverage
  `AuthSession` to easily manage authentication and authorization. This is
  also an extractor, so it can be used directly in your `axum` handlers.
- **Support for Arbitrary Users and Backends**: Applications implement a
  couple of traits, `AuthUser` and `AuthnBackend`, allowing for any user
  type and any user management backend. Your database? Yep. LDAP? Sure. An
  auth provider? You bet.
- **User and Group Permissions**: Authorization is supported via the
  `AuthzBackend` trait, which allows applications to define custom
  permissions. Both user and group permissions are supported.
- **Convenient Route Protection**: Middleware for protecting access to
  routes is available via the `login_required` and `permission_required`
  macros, and via the `require` builder (`require-builder` feature). The
  builder is the long-term primary surface; macros are convenience wrappers
  over the same behavior.
- **Rock-solid Session Management**: Uses [`tower-sessions`](https://github.com/maxcountryman/tower-sessions)
  for high-performing and ergonomic session management. _Look ma, no deadlocks!_

## 📦 Install

To use the crate in your project, add the following to your `Cargo.toml` file:

```toml
[dependencies]
axum-login = "0.18.0"
```

## 🤸 Usage

We recommend reviewing our [`sqlite` example][sqlite-example]. There is also a [template for `cargo-generate` using postgres](https://gitlab.com/maxhambraeus/axum-login-postgres-template).

> [!NOTE]
> See the [crate documentation][docs] for usage information.

### Builder quick start

```rust
use axum_login::require::{RedirectHandler, Require};
use axum_login::{AuthUser, AuthnBackend, UserId};

#[derive(Clone, Debug)]
struct User;

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        0
    }

    fn session_auth_hash(&self) -> &[u8] {
        &[]
    }
}

#[derive(Clone)]
struct Backend;

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = ();
    type Error = std::convert::Infallible;

    async fn authenticate(
        &self,
        _: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(Some(User))
    }

    async fn get_user(
        &self,
        _: &UserId<Self>,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(Some(User))
    }
}

let require = Require::<Backend>::builder()
    .unauthenticated(RedirectHandler::new().login_url("/login"))
    .build();
```

You can customize access logic with `.decision(...)`, which receives an
`AuthSession` plus `Arc<state>` when you build with shared state.

## ✅ Behavior Contract

The middleware surfaces follow the same contract:

- If the request is unauthenticated, the unauthenticated handler is used.
- If the request is authenticated but not authorized, the unauthorized handler is used.
- Redirect fallbacks preserve explicit redirect query parameters if already present and otherwise append the configured redirect field.
- Redirect construction errors return `500 Internal Server Error`.

## 🧩 Feature Flags

- `require-builder`: Enables the builder-based `require` module, which is the primary middleware surface.
- `macros-middleware`: Enables the `login_required!` and `permission_required!` macros. These are convenience wrappers over the builder and are enabled by default.

Example (builder only, no macros):

```toml
[dependencies]
axum-login = { version = "0.18.0", default-features = false, features = ["require-builder"] }
```

## 🦺 Safety

This crate uses `#![forbid(unsafe_code)]` to ensure everything is implemented in 100% safe Rust.

## 🛟 Getting Help

We've put together a number of [examples][examples] to help get you started. You're also welcome to [open a discussion](https://github.com/maxcountryman/axum-login/discussions/new?category=q-a) and ask additional questions you might have.

## 👯 Contributing

We appreciate all kinds of contributions, thank you!

[sqlite-example]: https://github.com/maxcountryman/axum-login/tree/main/examples/sqlite
[examples]: https://github.com/maxcountryman/axum-login/tree/main/examples
[docs]: https://docs.rs/axum-login

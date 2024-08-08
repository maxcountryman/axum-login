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
  routes are provided via the `login_required` and `permission_required`
  macros. Or bring your own by using `AuthSession` directly with
  `from_fn`.
- **Rock-solid Session Management**: Uses [`tower-sessions`](https://github.com/maxcountryman/tower-sessions)
  for high-performing and ergonomic session management. _Look ma, no deadlocks!_

## 📦 Install

To use the crate in your project, add the following to your `Cargo.toml` file:

```toml
[dependencies]
axum-login = "0.15.3"
```

## 🤸 Usage

We recommend reviewing our [`sqlite` example][sqlite-example]. There is also a [template for `cargo-generate` using postgres](https://gitlab.com/maxhambraeus/axum-login-postgres-template).

> [!NOTE]
> See the [crate documentation][docs] for usage information.

## 🦺 Safety

This crate uses `#![forbid(unsafe_code)]` to ensure everything is implemented in 100% safe Rust.

## 🛟 Getting Help

We've put together a number of [examples][examples] to help get you started. You're also welcome to [open a discussion](https://github.com/maxcountryman/axum-login/discussions/new?category=q-a) and ask additional questions you might have.

## 👯 Contributing

We appreciate all kinds of contributions, thank you!

[sqlite-example]: https://github.com/maxcountryman/axum-login/tree/main/examples/sqlite
[examples]: https://github.com/maxcountryman/axum-login/tree/main/examples
[docs]: https://docs.rs/axum-login

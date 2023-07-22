# Unreleased

**BREAKING CHANGES**:

- Use associated type `Error` in `UserStore` instead of eyre for error handling [#69](https://github.com/maxcountryman/axum-login/pull/69)
- Pass `&pool` to `sqlx::query` calls instead of a `&mut conn`, [(example)](https://github.com/maxcountryman/axum-login/pull/83/commits/ca3a4a0a3f7960f21147dfa093b41e01a1510625#diff-a1e8ba9587c151f4568fe2394889e8733a428bf67bfd62be7f3b91d6860cf54d)
- Support dropped for Mysql Server `mssql` (v0.5.0 last supported version)

**OTHER CHANGES**:
- `sqlx` library bumped to version `0.7`
- added support for [`libsql-client-rs`](https://github.com/libsql/libsql-client-rs) via crate `axum-login-libsql`

# 0.5.0

**BREAKING CHANGES**:

- Parametrize the `UserId` type (formerly hard-coded to `String`) in `AuthUser`, `AuthContext`, and `RequireAuthorizationLayer`.
- `SqlxStore`: Remove `with_table_name` and `with_column_name` in favor of `with_query`.

**OTHER CHANGES**:

- Add this changelog :tada:
- Extend .gitignore
- Bump `axum-sessions` to 0.5.0

# 0.4.1

- Expose `sqlx_store::SqlxStore` [PR #31](https://github.com/maxcountryman/axum-login/pull/31)
- Update README example

# 0.4.0

- Bump Axum to 0.6.0
- Introduce a `secrecy` feature

# 0.3.0

- Implement role bounds
- Implement `PartialOrd` for `Role`
- Implement a role-based `RequireAuthorizationLayer`
- Implement basic RBAC support
- Add an example to require a special user field value
- Remove `std::fmt::Debug` from `AuthUser` requirements
- Add `oauth` example

# 0.2.0

- General fixes and improvements

# 0.1.0

- Initial release :tada:

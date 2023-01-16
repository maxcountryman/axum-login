# 0.5.0
**BREAKING CHANGES**:
- Parametrize the `UserId` type (formerly hard-coded to `String`) in `AuthUser`, `AuthContext`, and `RequireAuthorizationLayer`.
- `SqlxStore`: Remove `with_table_name` and `with_column_name` in favor of `with_query`.

**OTHER CHANGES**:
- Add this changelog :tada:
- Extend .gitignore

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

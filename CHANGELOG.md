# 0.5.0
**BREAKING CHANGES**: 
- `SqlxStore`: remove support for `table_name` field in the struct in favor of the whole user-loading `query` override mechanism.

**OTHER CHANGES**:
- Add this changelog :tada:
- extend .gitignore

# 0.4.1
- expose sqlx_store::SqlxStore [PR #31](https://github.com/maxcountryman/axum-login/pull/31)
- update README example
# 0.4.0
- Bump Axum to 0.6.0
- Introduce a `secrecy` feature
# 0.3.0
- Implement role bounds
- Implement `PartialOrd` for `Role`
- Implement a role-based `RequireAuthorizationLayer`
- Implement basic RBAC support
- Add an example to require a special user field value
- Remove std::fmt::Debug from AuthUser requirements
- Add session csrf_state and logging
- Add oauth example
# 0.2.0
- General fixes and improvements
# 0.1.0
- Initial release :tada:
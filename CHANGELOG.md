# Unreleased

# 0.15.3

- Update dev dependencies; placate docs.rs

# 0.15.2

- Avoid unnecessary clone #225

# 0.15.1

- Replace `ring` with `subtle` #216

This makes using `axum-login` with targets like `wasm32-unknown-unknown` easier, as `ring` required C and assembly whereas `subtle` is a pure Rust constant time comparator.

# 0.15.0

- Update `tower-sessions` to 0.12.0

As of this update, signed and encrypted session cookies are supported.

# 0.14.0

- Update `tower-sessions` to 0.11.0

This updates `tower-sessions` to its latest release, which itself contains breaking changes.

Please review [those changes](https://github.com/maxcountryman/tower-sessions/blob/main/CHANGELOG.md#0110) for more details.

# 0.13.1

- Record user id on span when available. [#160](https://github.com/maxcountryman/axum-login/pull/160)

# 0.13.0

**Breaking Changes**

- Update `tower-sessions` to 0.10.0

This updates `tower-sessions` to its latest release, which itself contains breaking changes, especially with regard to previously-bundled session stores.

Please review [those changes](https://github.com/maxcountryman/tower-sessions/blob/main/CHANGELOG.md#0100) for more details.

# 0.12.0

**Breaking Changes**

- Make service infallible.

This follows along with the upstream changes to `tower-sessions`, where
we made it such that the sessions middleware will not directly result in
an error.

Here we do the same and in doing so are able to use the layer directly
with `axum`. This should reduce boilerplate.

# 0.11.3

- Relax trait bounds such that e.g. `Credentials` do not require `Clone`. #[#157](https://github.com/maxcountryman/axum-login/pull/157)

# 0.11.2

- Ensure correct redirect uri query handling. [#155](https://github.com/maxcountryman/axum-login/pull/155)

# 0.11.1

- Address request URI prefix truncation in nested routes by using `OriginalUri` extractor. [#153](https://github.com/maxcountryman/axum-login/pull/153)

# 0.11.0

**Breaking Changes**

- Update `tower-sessions` to 0.8.0; this introduces lazy sessions. [#132](https://github.com/maxcountryman/axum-login/pull/132)

This is a significant update to the session API, which now requires awaiting its methods. That said, changes to this crate are fairly minimal.

# 0.10.2

- Ensure `http` is referenced apropriately in macros.

# 0.10.1

- Ensure `predicate_required` is invoked correctly.

# 0.10.0

**Breaking Changes**

- Update `tower-sessions` to 0.7.0.

This includes support for `axum` 0.7.0.

# 0.9.0

**Breaking Changes**

- Update `tower-sessions` to 0.6.0; this removes `replace_if_equal` and addressed a performance bottleneck.

** Other Changes**

- Make `DATA_KEY` configurable. [#109](https://github.com/maxcountryman/axum-login/pull/109)

# 0.8.0

**Breaking changes**

- Update `tower-sessions` to 0.5.0; this changes the default session cookie name from "tower.sid" to "id".

Note that applications using the old default, "tower.sid", may continue to do so without disruption by specifying [`with_name("tower.sid")`](https://docs.rs/tower-sessions/latest/tower_sessions/service/struct.SessionManagerLayer.html#method.with_name).

**Other changes**

- Ensure session error type is accessible. [#120](https://github.com/maxcountryman/axum-login/pull/120)

# 0.7.3

- Fix `permission_required` macro. [#116](https://github.com/maxcountryman/axum-login/pull/116) and 7a6720a

# 0.7.2

- Cycle ID only as logging in. [#115](https://github.com/maxcountryman/axum-login/pull/115)
- Ensure anonymous sessions are verified. [#113](https://github.com/maxcountryman/axum-login/pull/113)

# 0.7.1

- Ensure middleware-producing macros (`login_required`, `permission_required`, and `predicate_required`) use crate dependencies.
- Re-organize into a workspace such that examples are self-contained crates.

# 0.7.0

⚠️ **This crate has been rewritten from the ground up.** ⚠️

We have entirely reimagined this crate's API, having now rewritten it to use `tower-sessions`.

The upshot of this is issues with deadlocks are a thing of the past. However, applications that rely on prior versions of the crate will have to evaluate the new API and decide if it's appropriate to migrate or not.

Please review [the documentation](https://docs.rs/axum-login/0.7.0/axum_login/index.html) for an overview of the new API.

# 0.6.0

**BREAKING CHANGES**:

- Provide `User` without `Option` [#70](https://github.com/maxcountryman/axum-login/pull/70)
- Use associated type `Error` in `UserStore` instead of eyre for error handling [#69](https://github.com/maxcountryman/axum-login/pull/69)
- Make `role_bounds` optional [#67](https://github.com/maxcountryman/axum-login/pull/67)

**OTHER CHANGES**

- Introduce `DefaultQueryProvider` for `sqlx` stores [#72](https://github.com/maxcountryman/axum-login/pull/72)
- Update `tower` to `0.4.0`
- Add optional redirect in `RequireAuthorizationLayer`

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

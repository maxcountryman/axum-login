# AGENTS

This repo is a workspace with the library at `axum-login/` and examples under
`examples/*`.

## Expectations
- Prefer the builder-based `require` API for new docs/examples; macros are legacy
  conveniences.
- Keep public API changes breaking only in breaking releases; document in
  `CHANGELOG.md`.
- Avoid unnecessary cloning; favor `Arc` where shared state is needed.
- Keep docs and examples in sync with the library API.

## Style
- Run `cargo fmt` (or `cargo +nightly fmt --all -- --check` in CI).
- Clippy is enforced: `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## Tests
- Full suite: `cargo test` (includes unit, integration, doc tests).
- Targeted runs are ok while iterating, but re-run full suite before shipping.

## Release hygiene
- Update `CHANGELOG.md` for net-new changes relative to `main`.
- Keep commit messages descriptive and documentation-friendly.

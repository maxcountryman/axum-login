//! # Overview
//!
//! This crate provides user authentication and authorization as a `tower`
//! middleware.
//!
//! If offers:
//!
//! - **Easy Login Management:** Methods for logging in, logging out, and
//!   accessing the current user.
//! - **An `axum` Extractor for [`Auth`]:** Applications built with `axum` can
//!   use `Auth` as an extractor directly in their handlers. This makes using
//!   manaing user authentication as easy as including `Auth` in your handler.
//! - **Automatic User Loading:** Users are loaded from a `UserStore`
//!   implementation. Stores can be a database or external identity provider,
//!   `axum-login` handles loading users from the store automatically.
#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_debug_implementations,
    missing_docs
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod auth;
mod extract;
mod middleware;
mod service;
mod user_store;

pub use auth::Auth;
pub use middleware::{require_authn, require_authz};
pub use service::{LoginManager, LoginManagerLayer};
pub use user_store::UserStore;

//! # Overview
//!
//! This crate provides user identification, authentication, and authorization
//! as a `tower` middleware.
//!
//! If offers:
//!
//! - **User Identification, Authentication, and Authorization**: Leverage
//!   [`AuthSession`] to easily manage authentication and authorization. This is
//!   also an extractor, so it can be used directly in your `axum` handlers.
//! - **Support for Arbitrary Users and Backends**: Applications implement a
//!   couple of traits, [`AuthUser`] and [`AuthnBackend`], allowing for any user
//!   type and any user management backend. Your database? Yep. LDAP? Sure. An
//!   auth provider? You bet.
//! - **User and Group Permissions**: Authorization is supported via the
//!   [`AuthzBackend`] trait, which allows applications to define custom
//!   permissions. Both user and group permissions are supported.
//! - **Convenient Route Protection**: Middleware for protecting access to
//!   routes are provided via the [`login_required!`] and
//!   [`permission_required!`] macros. Or bring your own by using
//!   [`AuthSession`] directly with [`from_fn`](axum::middleware::from_fn).
//! - **Rock-solid Session Management**: Uses [`tower-sessions`](tower_sessions)
//!   for high-performing and ergonomic session management. *Look ma, no
//!   deadlocks!*
#![warn(clippy::all, nonstandard_style, future_incompatible, missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use backend::{AuthUser, AuthnBackend, AuthzBackend, UserId};
pub use service::{AuthManager, AuthManagerLayer};
pub use session::AuthSession;

mod backend;
mod extract;
mod middleware;
mod service;
mod session;

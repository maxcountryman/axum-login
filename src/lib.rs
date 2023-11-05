//! # Overview
//!
//! This crate provides user authentication and authorization as a `tower`
//! middleware.
//!
//! If offers:
//!
//! - **Easy Login Management:** Methods for logging in, logging out, and
//!   accessing the current user and middleware for protecting routes based on
#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_debug_implementations,
    missing_docs
)]
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

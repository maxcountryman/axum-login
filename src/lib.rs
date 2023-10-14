#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_debug_implementations
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

#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_debug_implementations
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod extract;
mod service;
mod user_store;

pub use extract::{require_authn, require_authz};
pub use service::{Auth, LoginManager, LoginManagerLayer};
pub use user_store::UserStore;

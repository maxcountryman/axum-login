#![warn(
    clippy::all,
    nonstandard_style,
    future_incompatible,
    missing_debug_implementations
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod auth;
mod auth_state;
#[cfg(feature = "sqlx-store")]
mod sqlx_store;
mod user_store;

pub use auth::{require_auth, Auth};
pub use auth_state::AuthState;
#[cfg(feature = "sqlite-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite-store")))]
pub use sqlx_store::SqliteUserStore;
pub use user_store::UserStore;

use std::{fmt::Display, error::Error};

use axum_login::axum_sessions::async_session;


#[derive(Debug)]
pub enum Errors {
    DbExecutionError(async_session::Error),
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Errors::DbExecutionError(e) => write!(f, "DbExecutionError: {}", e),
        }
    }
}
impl Error for Errors {}

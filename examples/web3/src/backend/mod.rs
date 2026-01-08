mod state;
mod user;

use std::str::FromStr;

use axum_login::{AuthnBackend, UserId};
use serde::Deserialize;
use siwe::{Message, VerificationOpts};
use sqlx::SqlitePool;

pub use state::AppState;
pub use user::User;

use crate::store::Store;

#[derive(Debug, Clone)]
pub struct Backend {
    state: AppState,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub message: String,
    pub signature: String,
}

impl Backend {
    pub fn new(db: SqlitePool) -> Self {
        Self {
            state: AppState::new(db),
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        self.state.initialize().await
    }

    async fn get_or_create_user(&self, address: &[u8; 20]) -> Result<User, sqlx::Error> {
        let addr_prefixed_lowercase = format!("0x{}", hex::encode(address)).to_lowercase();
        let user: Option<User> = sqlx::query_as("select * from users where address = ?")
            .bind(addr_prefixed_lowercase.as_str())
            .fetch_optional(&self.state().db)
            .await?;

        if let Some(user) = user {
            return Ok(user);
        }

        let user =
            sqlx::query_as("insert into users (username, address) values (?, ?) returning *")
                .bind(addr_prefixed_lowercase.as_str())
                .bind(addr_prefixed_lowercase.as_str())
                .fetch_one(&self.state().db)
                .await?;

        Ok(user)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("SIWE verification failed: {0}")]
    Siwe(#[from] siwe::VerificationError),
    #[error("Invalid message: {0}")]
    InvalidMessage(siwe::ParseError),
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid signature")]
    InvalidSignature,
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let message = Message::from_str(creds.message.as_str())
            .map_err(|e| BackendError::InvalidMessage(e))?;

        let nonce = self
            .state
            .get_nonce(&message.nonce)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => BackendError::InvalidNonce,
                _ => BackendError::Sqlx(e),
            })?;

        let now = time::OffsetDateTime::now_utc();

        if nonce.expires_at < now {
            let _ = self.state.delete_nonce(&message.nonce).await;
            return Err(BackendError::InvalidNonce);
        }

        let opts = VerificationOpts {
            timestamp: Some(now),
            ..Default::default()
        };
        let sig = hex::decode(creds.signature).map_err(|_| BackendError::InvalidSignature)?;
        message
            .verify(&sig, &opts)
            .await
            .map_err(|e| BackendError::Siwe(e))?;

        let user = self.get_or_create_user(&message.address).await?;
        let _ = self.state.delete_nonce(&message.nonce).await;

        Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.state().db)
            .await?;

        Ok(user)
    }
}

pub type AuthSession = axum_login::AuthSession<Backend>;

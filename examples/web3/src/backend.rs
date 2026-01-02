use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    pub username: String,
    pub address: String,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("address", &self.address)
            .finish()
    }
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        // In a real app, you might want a separate session token or hash that changes on password/key change.
        // For SIWE, the address is static, but maybe we can use a nonce or something if we stored it.
        // For this example, we'll just check the address bytes.
        self.address.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct Backend {
    db: SqlitePool,
}

impl Backend {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("SIWE verification failed: {0}")]
    Siwe(#[from] siwe::VerificationError),
    #[error("Invalid message")]
    InvalidMessage,
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        #[allow(unused)] creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(None)
        // let message =
        //     Message::from_str(&creds.message).map_err(|_| BackendError::InvalidMessage)?;

        // // Verify the signature.
        // let signature_bytes = hex::decode(
        //     creds
        //         .signature
        //         .strip_prefix("0x")
        //         .unwrap_or(&creds.signature),
        // )
        // .map_err(|_| BackendError::InvalidMessage)?;

        // // Note: In a real app, you should check the nonce and domain here.
        // // message.verify(&signature_bytes, &domain, &nonce, &timestamp)?;
        // message
        //     .verify(&signature_bytes, &VerificationOpts::default())
        //     .await
        //     .map_err(BackendError::Siwe)?;

        // let address = hex::encode(message.address);
        // let address_prefixed = format!("0x{}", address);

        // // Find or create user.
        // // In this example, we accept any valid signature and create a user if they don't exist.
        // // We use the address as the username for simplicity.
        // let user = sqlx::query_as::<_, User>(
        //     r#"
        //     INSERT INTO users (username, address)
        //     VALUES (?, ?)
        //     ON CONFLICT(address) DO UPDATE SET username=excluded.username
        //     RETURNING *
        //     "#,
        // )
        // .bind(&address_prefixed)
        // .bind(&address_prefixed)
        // .fetch_one(&self.db)
        // .await?;

        // Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await?;

        Ok(user)
    }
}

pub type AuthSession = axum_login::AuthSession<Backend>;

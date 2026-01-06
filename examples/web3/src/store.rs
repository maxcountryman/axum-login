use sqlx::Error;

#[allow(unused)]
pub struct Nonce {
    pub nonce: String,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}

pub trait Store {
    async fn create_nonce_table(&self) -> Result<(), Error>;
    async fn create_nonce(
        &self,
        nonce: &str,
        created_at: &time::OffsetDateTime,
        expires_at: &time::OffsetDateTime,
    ) -> Result<(), Error>;
    async fn delete_nonce(&self, nonce: &str) -> Result<(), Error>;
    async fn delete_expired_nonce(&self) -> Result<(), Error>;
    async fn get_nonce(&self, nonce: &str) -> Result<Nonce, Error>;
}

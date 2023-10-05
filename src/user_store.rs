use async_trait::async_trait;

#[async_trait]
pub trait UserStore<User, UserId>: Send + Sync {
    type Error: std::error::Error;

    async fn load(&self, user_id: &UserId) -> Result<Option<User>, Self::Error>;
}

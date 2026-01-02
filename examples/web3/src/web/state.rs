use sqlx::SqlitePool;

use crate::store::{Nonce, Store};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

impl AppState {
    pub fn new(db: SqlitePool) -> Self {
        Self { db }
    }

    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        self.create_nonce_table().await?;
        Ok(())
    }
}

impl Store for AppState {
    async fn create_nonce_table(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "
            CREATE TABLE IF NOT EXISTS nonces (
                id INTEGER PRIMARY KEY,
                nonce TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            );
        ",
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn delete_nonce(&self, nonce: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM nonces WHERE nonce = ?")
            .bind(nonce)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn delete_expired_nonce(&self) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM nonces WHERE expires_at < CURRENT_TIMESTAMP")
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn create_nonce(
        &self,
        nonce: &str,
        created_at: &time::OffsetDateTime,
        expires_at: &time::OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO nonces (nonce, created_at, expires_at) VALUES (?, ?, ?)")
            .bind(nonce)
            .bind(created_at)
            .bind(expires_at)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn get_nonce(&self, nonce: &str) -> Result<Nonce, sqlx::Error> {
        let (nonce, created_at, expires_at): (String, time::OffsetDateTime, time::OffsetDateTime) =
            sqlx::query_as("SELECT nonce, created_at, expires_at FROM nonces WHERE nonce = ?")
                .bind(&nonce)
                .fetch_one(&self.db)
                .await
                .unwrap();

        Ok(Nonce {
            nonce,
            created_at,
            expires_at,
        })
    }
}

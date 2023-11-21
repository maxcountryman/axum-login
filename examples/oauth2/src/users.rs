use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    url::Url,
    AuthorizationCode, CsrfToken, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    pub username: String,
    pub access_token: String,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("access_token", &"[redacted]")
            .finish()
    }
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.access_token.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    login: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),
}

#[derive(Debug, Clone)]
pub struct Backend {
    db: SqlitePool,
    client: BasicClient,
}

impl Backend {
    pub fn new(db: SqlitePool, client: BasicClient) -> Self {
        Self { db, client }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client.authorize_url(CsrfToken::new_random).url()
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Ensure the CSRF state has not been tampered with.
        if creds.old_state.secret() != creds.new_state.secret() {
            return Ok(None);
        };

        // Process authorization code, expecting a token response back.
        let token_res = self
            .client
            .exchange_code(AuthorizationCode::new(creds.code))
            .request_async(async_http_client)
            .await
            .map_err(Self::Error::OAuth2)?;

        // Use access token to request user info.
        let user_info = reqwest::Client::new()
            .get("https://api.github.com/user")
            .header(USER_AGENT, "axum-login") // See: https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#user-agent-required
            .header(
                AUTHORIZATION,
                format!("Bearer {}", token_res.access_token().secret()),
            )
            .send()
            .await
            .map_err(Self::Error::Reqwest)?
            .json::<UserInfo>()
            .await
            .map_err(Self::Error::Reqwest)?;

        // Persist user in our database so we can use `get_user`.
        let user = sqlx::query_as(
            r#"
            insert into users (username, access_token)
            values (?, ?)
            on conflict(username) do update
            set access_token = excluded.access_token
            returning *
            "#,
        )
        .bind(user_info.login)
        .bind(token_res.access_token().secret())
        .fetch_one(&self.db)
        .await
        .map_err(Self::Error::Sqlx)?;

        Ok(Some(user))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Self::Error::Sqlx)?)
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;

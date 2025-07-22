use axum::http::header::{AUTHORIZATION, USER_AGENT};
use axum_login::{AuthUser, AuthnBackend, UserId};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    url::Url,
    AuthorizationCode, CsrfToken, EndpointNotSet, EndpointSet, TokenResponse,
};
use password_auth::verify_password;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use tokio::task;

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    id: i64,
    pub username: String,
    pub password: Option<String>,
    pub access_token: Option<String>,
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"[redacted]")
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
        if let Some(access_token) = &self.access_token {
            return access_token.as_bytes();
        }

        if let Some(password) = &self.password {
            return password.as_bytes();
        }

        &[]
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum Credentials {
    Password(PasswordCreds),
    OAuth(OAuthCreds),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordCreds {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCreds {
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
    OAuth2(BasicRequestTokenError<<reqwest::Client as oauth2::AsyncHttpClient<'static>>::Error>),

    #[error(transparent)]
    TaskJoin(#[from] task::JoinError),
}

pub type BasicClientSet =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Debug, Clone)]
pub struct Backend {
    db: SqlitePool,
    client: BasicClientSet,
    http_client: reqwest::Client,
}

impl Backend {
    pub fn new(db: SqlitePool, client: BasicClientSet) -> Self {
        let http_client: reqwest::Client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Client should build");
        Self {
            db,
            client,
            http_client,
        }
    }

    pub fn authorize_url(&self) -> (Url, CsrfToken) {
        self.client.authorize_url(CsrfToken::new_random).url()
    }
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        match creds {
            Self::Credentials::Password(password_cred) => {
                let user: Option<Self::User> = sqlx::query_as(
                    "select * from users where username = ? and password is not null",
                )
                .bind(password_cred.username)
                .fetch_optional(&self.db)
                .await
                .map_err(Self::Error::Sqlx)?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                // `spawn_blocking`.
                task::spawn_blocking(|| {
                    // We're using password-based authentication: this works by comparing our form
                    // input with an argon2 password hash.
                    Ok(user.filter(|user| {
                        let Some(ref password) = user.password else {
                            return false;
                        };
                        verify_password(password_cred.password, password).is_ok()
                    }))
                })
                .await?
            }

            Self::Credentials::OAuth(oauth_creds) => {
                // Ensure the CSRF state has not been tampered with.
                if oauth_creds.old_state.secret() != oauth_creds.new_state.secret() {
                    return Ok(None);
                };

                // Process authorization code, expecting a token response back.
                let token_res = self
                    .client
                    .exchange_code(AuthorizationCode::new(oauth_creds.code))
                    .request_async(&self.http_client)
                    .await
                    .map_err(Self::Error::OAuth2)?;

                // Use access token to request user info.
                let user_info = reqwest::Client::new()
                    .get("https://api.github.com/user")
                    .header(USER_AGENT.as_str(), "axum-login") // See: https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#user-agent-required
                    .header(
                        AUTHORIZATION.as_str(),
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
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Self::Error::Sqlx)
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;

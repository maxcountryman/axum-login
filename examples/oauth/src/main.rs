//! To run this example you need to create your own Google OAuth2 credentials https://support.google.com/cloud/answer/6158849?hl=en
//! Copy the .env.example to a .env file and fill in the CLIENT_ID and
//! CLIENT_SECRET Run with
//!
//! ```not_rust
//! cd examples/oauth && cargo run example-oauth
//! ```
//!
//! Or you can run from the examples dir by passing the required env vars
//! ```not_rust
//! cd examples/oauth && CLIENT_ID=xxx CLIENT_SECRET=yyy cargo run -p example-oauth
//! ```

use std::env;

use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
    routing::get,
    Extension, Router,
};
use axum_login::{
    axum_sessions::{
        async_session::MemoryStore,
        extractors::{ReadableSession, WritableSession},
        SameSite, SessionLayer,
    },
    secrecy::SecretVec,
    AuthLayer, AuthUser, RequireAuthorizationLayer, SqliteStore,
};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use rand::Rng;
use serde::Deserialize;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

#[derive(Debug, Default, Clone, sqlx::FromRow)]
struct User {
    id: i64,
    password_hash: String,
    name: String,
}

impl AuthUser<i64> for User {
    fn get_id(&self) -> i64 {
        self.id
    }

    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.password_hash.clone().into())
    }
}

type AuthContext = axum_login::extractors::AuthContext<i64, User, SqliteStore<User>>;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = MemoryStore::new();
    let session_layer = SessionLayer::new(session_store, &secret)
        .with_secure(false)
        .with_same_site_policy(SameSite::Lax);

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "oauth/user_store.db".to_string());

    let pool = SqlitePoolOptions::new().connect(&db_url).await.unwrap();

    let user_store = SqliteStore::<User>::new(pool.clone());
    let auth_layer = AuthLayer::new(user_store, &secret);

    let oauth_client = build_oauth_client();

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .route_layer(RequireAuthorizationLayer::<i64, User>::login())
        .route("/login", get(login_handler))
        .route("/auth/google/callback", get(oauth_callback_handler))
        .route("/logout", get(logout_handler))
        .layer(Extension(oauth_client))
        .layer(Extension(pool))
        .layer(auth_layer)
        .layer(session_layer);

    axum::Server::bind(&"127.0.0.1:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: CsrfToken,
}

async fn oauth_callback_handler(
    mut auth: AuthContext,
    Query(query): Query<AuthRequest>,
    Extension(pool): Extension<SqlitePool>,
    Extension(oauth_client): Extension<BasicClient>,
    session: ReadableSession,
) -> impl IntoResponse {
    println!("Running oauth callback {query:?}");
    // Compare the csrf state in the callback with the state generated before the
    // request
    let original_csrf_state: CsrfToken = session.get("csrf_state").unwrap();
    let query_csrf_state = query.state.secret();
    let csrf_state_equal = original_csrf_state.secret() == query_csrf_state;

    drop(session);

    if !csrf_state_equal {
        println!("csrf state is invalid, cannot login",);

        // Return to some error
        return Redirect::to("/protected");
    }

    println!("Getting oauth token");
    // Get an auth token
    let _token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .unwrap();

    // Do something with the token
    // ...
    println!("Getting db connection");

    // Fetch the user and log them in
    let mut conn = pool.acquire().await.unwrap();
    println!("Getting user");
    let user: User = sqlx::query_as("select * from users where id = 1")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    println!("Got user {user:?}. Logging in.");
    auth.login(&user).await.unwrap();

    println!("Logged in the user: {user:?}");

    Redirect::to("/protected")
}

async fn login_handler(
    Extension(client): Extension<BasicClient>,
    mut session: WritableSession,
) -> impl IntoResponse {
    // Generate the authorization URL to which we'll redirect the user.
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.profile".to_string(),
        ))
        .url();

    // Store the csrf_state in the session so we can assert equality in the callback
    session.insert("csrf_state", csrf_state).unwrap();

    // Redirect to your oauth service
    Redirect::to(auth_url.as_ref())
}

async fn logout_handler(mut auth: AuthContext) {
    dbg!("Logging out user: {}", &auth.current_user);
    auth.logout().await;
}

async fn protected_handler(Extension(user): Extension<User>) -> impl IntoResponse {
    format!("Logged in as: {}", user.name)
}

fn build_oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = "http://127.0.0.1:3000/auth/google/callback".to_string();

    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

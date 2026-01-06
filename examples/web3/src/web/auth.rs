use crate::backend::AuthSession;
use askama::Template;
use axum::Json;
use axum::{
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use http::StatusCode;

use crate::backend::{AppState, Credentials};

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(self::post::login))
        .route("/login", get(self::get::login))
        .route("/logout", get(self::get::logout))
}
mod get {
    use super::*;

    pub async fn login() -> Html<String> {
        Html(LoginTemplate {}.render().unwrap())
    }
    pub async fn logout(auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => (StatusCode::OK, "Logged out").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

mod post {
    use super::*;

    pub async fn login(
        auth_session: AuthSession,
        Json(creds): Json<Credentials>,
    ) -> impl IntoResponse {
        let user = match auth_session.authenticate(creds).await {
            Ok(Some(user)) => user,
            Ok(None) => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        if auth_session.login(&user).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        (StatusCode::OK, "Successfully logged in").into_response()
    }
}

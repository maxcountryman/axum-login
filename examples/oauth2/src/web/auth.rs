use askama::Template;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Router,
};
use axum_login::tower_sessions::Session;
use serde::Deserialize;

use crate::{users::AuthSession, web::oauth::CSRF_STATE_KEY};

pub const NEXT_URL_KEY: &str = "auth.next-url";

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub message: Option<String>,
    pub next: Option<String>,
}

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn router() -> Router<()> {
    Router::new()
        .route("/login", post(self::post::login))
        .route("/login", get(self::get::login))
        .route("/logout", get(self::get::logout))
}

mod post {
    use super::*;

    pub async fn login(
        auth_session: AuthSession,
        session: Session,
        Form(NextUrl { next }): Form<NextUrl>,
    ) -> impl IntoResponse {
        let (auth_url, csrf_state) = auth_session.backend.authorize_url();

        session
            .insert(CSRF_STATE_KEY, csrf_state.secret())
            .await
            .expect("Serialization should not fail.");

        session
            .insert(NEXT_URL_KEY, next)
            .await
            .expect("Serialization should not fail.");

        Redirect::to(auth_url.as_str()).into_response()
    }
}

mod get {
    use super::*;

    pub async fn login(Query(NextUrl { next }): Query<NextUrl>) -> LoginTemplate {
        LoginTemplate {
            message: None,
            next,
        }
    }

    pub async fn logout(mut auth_session: AuthSession) -> impl IntoResponse {
        match auth_session.logout().await {
            Ok(_) => Redirect::to("/login").into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

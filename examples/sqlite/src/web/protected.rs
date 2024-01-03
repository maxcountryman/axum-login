use askama::Template;
use axum::{response::IntoResponse, routing::get, Router};

use crate::users::User;

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate {
    username: String,
}

pub fn router() -> Router<()> {
    Router::new().route("/", get(self::get::protected))
}

mod get {
    use super::*;

    pub async fn protected(User { username, .. }: User) -> impl IntoResponse {
        ProtectedTemplate { username }
    }
}

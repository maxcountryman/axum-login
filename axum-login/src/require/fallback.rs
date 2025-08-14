use crate::require::{DEFAULT_LOGIN_URL, DEFAULT_REDIRECT_FIELD};
use crate::url_with_redirect_query;
use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::{Response, StatusCode};
use std::future::{ready, Future, Ready};

pub trait AsyncFallback<Req> {
    /// Future returned by the fallback handler
    type Future: Future<Output = Self::Response>;

    /// Type of the successful response
    type Response;

    fn fallback(&mut self, request: Request<Req>) -> Self::Future;
}

impl<F, ReqInBody, Fut, Res> AsyncFallback<ReqInBody> for F
where
    F: FnMut(Request<ReqInBody>) -> Fut,
    Fut: Future<Output = Res>,
{
    type Future = Fut;
    type Response = Res;

    fn fallback(&mut self, request: Request<ReqInBody>) -> Self::Future {
        (self)(request)
    }
}

#[derive(Clone)]
pub struct DefaultFallback;

impl<ReqInBody> AsyncFallback<ReqInBody> for DefaultFallback
where
    ReqInBody: Send + 'static,
{
    type Future = Ready<Response<Body>>;
    type Response = Response<Body>;

    fn fallback(&mut self, _request: Request<ReqInBody>) -> Self::Future {
        ready(
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized"))
                .unwrap(),
        )
    }
}

#[derive(Clone)]
pub(crate) struct InternalErrorFallback;

impl<ReqInBody> AsyncFallback<ReqInBody> for InternalErrorFallback {
    type Future = Ready<Response<Body>>;
    type Response = Response<Body>;

    fn fallback(&mut self, _request: Request<ReqInBody>) -> Self::Future {
        ready(
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal server error"))
                .unwrap(),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct RedirectFallback {
    pub redirect_field: Option<String>,
    pub login_url: Option<String>,
}

impl RedirectFallback {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn redirect_field(mut self, field: impl Into<String>) -> Self {
        self.redirect_field = Some(field.into());
        self
    }

    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }
}

impl<ReqInBody> AsyncFallback<ReqInBody> for RedirectFallback {
    type Future = Ready<axum::response::Response<Body>>; //TODO: currently have only async variant
    type Response = axum::response::Response<Body>;

    fn fallback(&mut self, req: Request<ReqInBody>) -> Self::Future {
        let login_url = self
            .login_url
            .clone()
            .unwrap_or(DEFAULT_LOGIN_URL.to_string());
        let redirect_field = self
            .redirect_field
            .clone()
            .unwrap_or(DEFAULT_REDIRECT_FIELD.to_string());

        let resp = match req.extensions().get::<OriginalUri>().cloned() {
            None => axum::response::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Internal Server Error".into())
                .unwrap(),
            Some(OriginalUri(original_uri)) => {
                let url =
                    url_with_redirect_query(&login_url, &redirect_field, original_uri).unwrap();
                axum::response::Response::builder()
                    .status(StatusCode::TEMPORARY_REDIRECT)
                    .header("Location", url.to_string())
                    .body("Redirecting...".into())
                    .unwrap()
            }
        };

        return ready(resp);
    }
}

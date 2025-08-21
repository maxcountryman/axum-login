use crate::require::{DEFAULT_LOGIN_URL, DEFAULT_REDIRECT_FIELD};
use crate::url_with_redirect_query;
use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::{HeaderName, HeaderValue, Response, StatusCode};
use std::collections::HashMap;
use std::future::{ready, Future, Ready};

pub trait AsyncFallbackHandler<Req> {
    /// Future returned by the handler
    type Future: Future<Output = Self::Response>;

    /// Type of the successful response
    type Response;

    fn handle(&mut self, request: Request<Req>) -> Self::Future;
}

impl<F, ReqInBody, Fut, Res> AsyncFallbackHandler<ReqInBody> for F
where
    F: FnMut(Request<ReqInBody>) -> Fut,
    Fut: Future<Output = Res>,
{
    type Future = Fut;
    type Response = Res;

    fn handle(&mut self, request: Request<ReqInBody>) -> Self::Future {
        (self)(request)
    }
}

#[derive(Clone)]
pub struct DefaultFallback;

impl<ReqInBody> AsyncFallbackHandler<ReqInBody> for DefaultFallback
where
    ReqInBody: Send + 'static,
{
    type Future = Ready<Response<Body>>;
    type Response = Response<Body>;

    fn handle(&mut self, _request: Request<ReqInBody>) -> Self::Future {
        ready(
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Unauthorized"))
                .unwrap(),
        )
    }
}

#[derive(Clone)]
pub struct DefaultRestrict;

impl<ReqInBody> AsyncFallbackHandler<ReqInBody> for DefaultRestrict
where
    ReqInBody: Send + 'static,
{
    type Future = Ready<Response<Body>>;
    type Response = Response<Body>;

    fn handle(&mut self, _request: Request<ReqInBody>) -> Self::Future {
        ready(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Forbidden"))
                .unwrap(),
        )
    }
}

#[derive(Clone)]
pub(crate) struct InternalErrorFallback;

impl<ReqInBody> AsyncFallbackHandler<ReqInBody> for InternalErrorFallback {
    type Future = Ready<Response<Body>>;
    type Response = Response<Body>;

    fn handle(&mut self, _request: Request<ReqInBody>) -> Self::Future {
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

impl<ReqInBody> AsyncFallbackHandler<ReqInBody> for RedirectFallback {
    type Future = Ready<axum::response::Response<Body>>; //PERF: currently have only async variant
    type Response = axum::response::Response<Body>;

    fn handle(&mut self, req: Request<ReqInBody>) -> Self::Future {
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

        ready(resp)
    }
}

/// Custom response fallback handler for flexible authentication failure responses
#[derive(Clone, Debug)]
pub struct SimpleResponseFallback {
    /// HTTP status code to return
    pub status_code: StatusCode,
    /// Response body content
    pub body: String,
    /// Content-Type header value
    pub content_type: String,
    /// Additional custom headers to include
    pub headers: HashMap<String, String>,
}

impl Default for SimpleResponseFallback {
    fn default() -> Self {
        Self {
            status_code: StatusCode::UNAUTHORIZED,
            body: "Authentication required".to_string(),
            content_type: "text/plain".to_string(),
            headers: HashMap::new(),
        }
    }
}

impl SimpleResponseFallback {
    /// Create a new CustomResponseFallback with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the HTTP status code
    pub fn status_code(mut self, status: StatusCode) -> Self {
        self.status_code = status;
        self
    }

    /// Set the response body
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the content type
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Add a custom header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Add multiple custom headers
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Create an HTML response
    pub fn html(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("text/html; charset=utf-8")
            .body(body)
    }

    /// Create a plain text response
    pub fn text(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("text/plain; charset=utf-8")
            .body(body)
    }

    /// Create an XML response
    pub fn xml(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("application/xml")
            .body(body)
    }

    /// Create a simple error page
    pub fn error_page(
        status: StatusCode,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let message = message.into();
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>{}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .error {{ background: #f8f9fa; border-left: 4px solid #dc3545; padding: 20px; }}
        h1 {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>{}</h1>
        <p>{}</p>
    </div>
</body>
</html>"#,
            title, title, message
        );
        Self::html(status, html)
    }
}

impl<ReqBody> AsyncFallbackHandler<ReqBody> for SimpleResponseFallback {
    type Future = Ready<Response<Body>>; //PERF: currently have only async variant
    type Response = Response<Body>;

    fn handle(&mut self, _req: Request<ReqBody>) -> Self::Future {
        //PERF: currently have only async variant
        let mut response_builder = Response::builder().status(self.status_code);

        // Set content type
        if let Ok(content_type) = HeaderValue::from_str(&self.content_type) {
            response_builder = response_builder.header("Content-Type", content_type);
        }

        // Build the response
        let mut response = response_builder
            .body(self.body.clone().into())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal Server Error"))
                    .unwrap()
            });

        for (name, value) in &self.headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers_mut().insert(header_name, header_value);
            }
        }

        ready(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn test_default_response() {
        let mut handler = SimpleResponseFallback::new();
        let request = Request::builder().body(()).unwrap();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_custom_headers() {
        let mut handler = SimpleResponseFallback::new().header("X-Custom-Header", "custom-value");

        let request = Request::builder().body(()).unwrap();
        let response = handler.handle(request).await;

        assert_eq!(
            response.headers().get("X-Custom-Header").unwrap(),
            "custom-value"
        );
        assert!(response
            .headers()
            .contains_key("Access-Control-Allow-Origin"));
    }
}

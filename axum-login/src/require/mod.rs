mod builder;
mod fallback;
mod service;

use crate::require::fallback::DefaultFallback;
use crate::require::service::RequireService;
use crate::AuthnBackend;
use axum::body::Body;
use axum::extract::Request;
use axum::response::Response;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower_layer::Layer;

const DEFAULT_LOGIN_URL: &str = "/signin";
const DEFAULT_REDIRECT_FIELD: &str = "next";
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
//TODO: Builder should be a feature imho
//TODO: there is a mess with how to name different handlers and their wrappers
//TODO: The current implementation of Handlers is subject to change
pub type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
pub type RestrictFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;
pub type FallbackFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;

pub struct Require<B, ST = (), T = Body, Fb = DefaultFallback>
where
    B: AuthnBackend,
    Fb: Send + 'static,
{
    pub predicate: PredicateStateFn<B, ST>,
    pub restrict: RestrictFn<T>,
    pub fallback: Fb,
    pub state: ST,
}

impl<B, Fb, ST, T> Require<B, ST, T, Fb>
where
    B: AuthnBackend,
    Fb: Clone + Send + Sync + 'static,
    ST: Clone,
{
    pub fn new(
        predicate: PredicateStateFn<B, ST>,
        restrict: RestrictFn<T>,
        fallback: Fb,
        state: ST,
    ) -> Self {
        Self {
            predicate,
            restrict,
            fallback,
            state,
        }
    }
}

//umm, manual clone, because of Body
impl<B, Fb, ST, T> Clone for Require<B, ST, T, Fb>
where
    Fb: Clone + Send + Sync + 'static,
    ST: Clone,
    B: Clone + AuthnBackend,
{
    fn clone(&self) -> Self {
        Self {
            predicate: self.predicate.clone(),
            restrict: self.restrict.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            // _marker: PhantomData,
        }
    }
}

impl<S, B, ST, T, Fb> Layer<S> for Require<B, ST, T, Fb>
where
    B: Clone + AuthnBackend + Send + Sync + 'static,
    Fb: Clone + Send + Sync + 'static,
    ST: Clone + Send + Sync + 'static,
{
    type Service = RequireService<S, B, ST, T, Fb>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            layer: self.clone(),
        }
    }
}

mod builder;
mod service;
// mod predicate;
// mod fallback;

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
//TODO: use own futures
//TODO: The current implementation of Handlers is subject to change
pub type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
pub type RestrictFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;
pub type FallbackFn<T> = Arc<dyn Fn(Request<T>) -> BoxFuture<'static, Response> + Send + Sync>;
pub struct Require<B: AuthnBackend, ST = (), T = Body> {
    pub predicate: PredicateStateFn<B, ST>,
    pub restrict: RestrictFn<T>,
    pub fallback: FallbackFn<T>,
    pub state: ST,
}

impl<B, ST, T> Require<B, ST, T>
where
    B: AuthnBackend,
    ST: Clone,
{
    pub fn new(
        predicate: PredicateStateFn<B, ST>,
        restrict: RestrictFn<T>,
        fallback: FallbackFn<T>,
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
impl<B, ST, T> Clone for Require<B, ST, T>
where
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

impl<S, B, ST, T> Layer<S> for Require<B, ST, T>
where
    B: Clone + AuthnBackend,
    ST: Clone,
{
    type Service = RequireService<S, B, ST, T>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            layer: self.clone(),
        }
    }
}

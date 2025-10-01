mod builder;
pub mod handler;
mod predicate;
mod service;

use crate::require::builder::RequireBuilder;
use crate::require::handler::{DefaultFallback, DefaultRestrict};
use crate::require::predicate::{DefaultPredicate, PredicateAsync};
use crate::require::service::RequireService;
use crate::AuthnBackend;
use axum::body::Body;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use tower_layer::Layer;

//TODO: relax bounds
const DEFAULT_LOGIN_URL: &str = "/signin";
const DEFAULT_REDIRECT_FIELD: &str = "next";
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type PredicateStateFn<B, ST> =
    Arc<dyn Fn(B, <B as AuthnBackend>::User, ST) -> BoxFuture<'static, bool> + Send + Sync>;
pub struct Require<
    B,
    ST = (),
    T = Body,
    Fb = DefaultFallback,
    Rs = DefaultRestrict,
    Pr = DefaultPredicate<B, ST>,
> where
    Fb: Send + 'static,
    Rs: Send + 'static,
    Pr: Send + 'static,
    B: AuthnBackend,
    T: Send + 'static,
{
    pub predicate: Pr,
    pub restrict: Rs,
    pub fallback: Fb,
    pub state: ST,
    _phantom: PhantomData<(B, fn() -> T)>, //Sync trick
}

impl<B, Fb, Rs, Pr, ST, T> Require<B, ST, T, Fb, Rs, Pr>
where
    B: AuthnBackend,
    Fb: Clone + Send + Sync + 'static,
    Rs: Clone + Send + Sync + 'static,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + std::marker::Send,
    T: std::marker::Send,
{
    pub fn new(predicate: Pr, restrict: Rs, fallback: Fb, state: ST) -> Self {
        Self {
            predicate,
            restrict,
            fallback,
            state,
            _phantom: PhantomData,
        }
    }
}

//umm, manual clone, because of Body
impl<B, Fb, Rs, ST, T, Pr> Clone for Require<B, ST, T, Fb, Rs, Pr>
where
    Fb: Clone + 'static + std::marker::Send,
    Rs: Clone + 'static + std::marker::Send,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + std::marker::Send,
    B: Clone + AuthnBackend,
    T: std::marker::Send,
{
    fn clone(&self) -> Self {
        Self {
            predicate: self.predicate.clone(),
            restrict: self.restrict.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            _phantom: PhantomData,
        }
    }
}
impl<B, T> Require<B, (), T>
where
    B: AuthnBackend,
    T: 'static + Send,
{
    #[inline]
    pub fn builder(
    ) -> RequireBuilder<B, (), T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ()>> {
        RequireBuilder::new()
    }
}
impl<B, ST, T> Require<B, ST, T>
where
    B: AuthnBackend,
    T: 'static + Send,
    ST: std::marker::Send + std::clone::Clone + std::marker::Sync,
    DefaultPredicate<B, ST>: PredicateAsync<B, ST>
{
    #[inline]
    pub fn builder_with_state(
        state: ST,
    ) -> RequireBuilder<B, ST, T, DefaultFallback, DefaultRestrict, DefaultPredicate<B, ST>> {
        RequireBuilder::new_with_state(state)
    }
}

impl<S, B, ST, T, Fb, Rs, Pr> Layer<S> for Require<B, ST, T, Fb, Rs, Pr>
where
    B: Clone + AuthnBackend + Send + Sync + 'static,
    Fb: Clone + Send + Sync + 'static,
    Rs: Clone + Send + Sync + 'static,
    Pr: Clone + Send + Sync + 'static,
    ST: Clone + Send + Sync + 'static,
    T: std::marker::Send + 'static,
{
    type Service = RequireService<S, B, ST, T, Fb, Rs, Pr>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            layer: self.clone(),
        }
    }
}

use tower_layer::Layer;
use crate::AuthnBackend;
use crate::require::Require;
use crate::require::service::RequireService;

use axum::body::Body;
use axum::extract::{OriginalUri, Request};

impl<S, B, ST, T> Layer<S> for Require<B, ST, T>
where
    B: Clone + AuthnBackend,
    ST: Clone,
{
    type Service = RequireService<S, B, ST, T>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireService {
            inner,
            predicate: self.predicate.clone(),
            fallback: self.fallback.clone(),
            state: self.state.clone(),
            restrict: self.restrict.clone(),
        }
    }
}

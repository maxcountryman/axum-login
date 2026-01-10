use std::collections::HashSet;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use axum_login::{
    login_required, permission_required,
    require::{PermissionsPredicate, RedirectHandler, Require},
    AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tower::ServiceExt;
use tower_sessions::SessionManagerLayer;
use tower_sessions_sqlx_store::{sqlx::SqlitePool, SqliteStore};

#[derive(Clone, Debug)]
struct User;

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        0
    }

    fn session_auth_hash(&self) -> &[u8] {
        &[]
    }
}

#[derive(Clone, Debug)]
struct Credentials;

#[derive(thiserror::Error, Debug)]
struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

#[derive(Clone)]
struct TestBackend;

impl AuthnBackend for TestBackend {
    type User = User;
    type Credentials = Credentials;
    type Error = Error;

    async fn authenticate(&self, _: Self::Credentials) -> Result<Option<Self::User>, Self::Error> {
        Ok(Some(User))
    }

    async fn get_user(
        &self,
        _: &<<TestBackend as AuthnBackend>::User as AuthUser>::Id,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(Some(User))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TestPermission {
    pub name: String,
}

impl From<&str> for TestPermission {
    fn from(name: &str) -> Self {
        TestPermission {
            name: name.to_string(),
        }
    }
}

impl AuthzBackend for TestBackend {
    type Permission = TestPermission;

    async fn get_user_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let perms: HashSet<Self::Permission> =
            HashSet::from_iter(["test.read".into(), "test.write".into()]);
        Ok(perms)
    }
}

macro_rules! setup_auth_layer {
    () => {{
        let pool = SqlitePool::connect(":memory:").await.unwrap();
        let session_store = SqliteStore::new(pool.clone());
        session_store.migrate().await.unwrap();

        let session_layer = SessionManagerLayer::new(session_store).with_secure(false);

        AuthManagerLayerBuilder::new(TestBackend, session_layer).build()
    }};
}

fn benchmark_unauthenticated(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (macro_app, builder_app) = runtime.block_on(async {
        let auth_layer = setup_auth_layer!();
        let macro_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(TestBackend))
            .layer(auth_layer.clone());
        let builder_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(Require::<TestBackend>::builder().build())
            .layer(auth_layer);
        (macro_app, builder_app)
    });

    let mut group = c.benchmark_group("unauthenticated_request");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "login_required"), |b| {
        let macro_app = macro_app.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder().uri("/").body(Body::empty()).unwrap();
            let res = macro_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "login_required"), |b| {
        let builder_app = builder_app.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder().uri("/").body(Body::empty()).unwrap();
            let res = builder_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        });
    });

    group.finish();
}

fn benchmark_authenticated(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (macro_app, macro_cookie, builder_app, builder_cookie) = runtime.block_on(async {
        let auth_layer = setup_auth_layer!();
        let macro_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(TestBackend))
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer.clone());
        let builder_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(Require::<TestBackend>::builder().build())
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer);

        let macro_cookie = macro_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();
        let builder_cookie = builder_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();

        (macro_app, macro_cookie, builder_app, builder_cookie)
    });

    let mut group = c.benchmark_group("authenticated_request");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "login_required"), |b| {
        let macro_app = macro_app.clone();
        let macro_cookie = macro_cookie.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder()
                .uri("/")
                .header(header::COOKIE, macro_cookie.clone())
                .body(Body::empty())
                .unwrap();
            let res = macro_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "login_required"), |b| {
        let builder_app = builder_app.clone();
        let builder_cookie = builder_cookie.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder()
                .uri("/")
                .header(header::COOKIE, builder_cookie.clone())
                .body(Body::empty())
                .unwrap();
            let res = builder_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        });
    });

    group.finish();
}

fn benchmark_permission_check(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (macro_app, macro_cookie, builder_app, builder_cookie) = runtime.block_on(async {
        let auth_layer = setup_auth_layer!();
        let macro_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(permission_required!(TestBackend, "test.read"))
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer.clone());

        let permissions: Vec<&str> = vec!["test.read"];
        let builder_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(
                Require::<TestBackend>::builder()
                    .decision(PermissionsPredicate::new().with_permissions(permissions))
                    .build(),
            )
            .route(
                "/login",
                axum::routing::get(|auth_session: AuthSession<TestBackend>| async move {
                    auth_session.login(&User).await.unwrap();
                }),
            )
            .layer(auth_layer);

        let macro_cookie = macro_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();
        let builder_cookie = builder_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();

        (macro_app, macro_cookie, builder_app, builder_cookie)
    });

    let mut group = c.benchmark_group("permission_check");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "permission_required"), |b| {
        let macro_app = macro_app.clone();
        let macro_cookie = macro_cookie.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder()
                .uri("/")
                .header(header::COOKIE, macro_cookie.clone())
                .body(Body::empty())
                .unwrap();
            let res = macro_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "permission_required"), |b| {
        let builder_app = builder_app.clone();
        let builder_cookie = builder_cookie.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder()
                .uri("/")
                .header(header::COOKIE, builder_cookie.clone())
                .body(Body::empty())
                .unwrap();
            let res = builder_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        });
    });

    group.finish();
}

fn benchmark_redirect_fallback(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (macro_app, builder_app) = runtime.block_on(async {
        let auth_layer = setup_auth_layer!();
        let macro_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(login_required!(TestBackend, login_url = "/login"))
            .layer(auth_layer.clone());
        let builder_app = Router::new()
            .route("/", axum::routing::get(|| async {}))
            .route_layer(
                Require::<TestBackend>::builder()
                    .unauthenticated(RedirectHandler::new().login_url("/login"))
                    .build(),
            )
            .layer(auth_layer);
        (macro_app, builder_app)
    });

    let mut group = c.benchmark_group("redirect_fallback");

    // Benchmark macro-based middleware with redirect
    group.bench_function(BenchmarkId::new("macro", "login_url_redirect"), |b| {
        let macro_app = macro_app.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder().uri("/").body(Body::empty()).unwrap();
            let res = macro_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        });
    });

    // Benchmark builder-based middleware with redirect
    group.bench_function(BenchmarkId::new("builder", "login_url_redirect"), |b| {
        let builder_app = builder_app.clone();
        b.to_async(&runtime).iter(|| async {
            let req = Request::builder().uri("/").body(Body::empty()).unwrap();
            let res = builder_app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_unauthenticated,
    benchmark_authenticated,
    benchmark_permission_check,
    benchmark_redirect_fallback
);
criterion_main!(benches);

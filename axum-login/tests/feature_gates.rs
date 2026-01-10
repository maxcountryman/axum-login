#[cfg(all(feature = "require-builder", not(feature = "macros-middleware")))]
mod require_builder_only {
    use axum_login::require::{RedirectHandler, Require};

    #[test]
    fn assert_builder_api_available() {
        let _layer = Require::<TestBackend>::builder()
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .build();
    }

    #[derive(Clone)]
    struct TestBackend;

    #[derive(Clone, Debug)]
    struct User;

    #[derive(Clone)]
    struct Credentials;

    #[derive(Debug)]
    struct Error;

    impl std::fmt::Display for Error {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Ok(())
        }
    }

    impl std::error::Error for Error {}

    impl axum_login::AuthUser for User {
        type Id = i64;

        fn id(&self) -> Self::Id {
            0
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    impl axum_login::AuthnBackend for TestBackend {
        type User = User;
        type Credentials = Credentials;
        type Error = Error;

        async fn authenticate(
            &self,
            _: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }

        async fn get_user(
            &self,
            _: &<<Self as axum_login::AuthnBackend>::User as axum_login::AuthUser>::Id,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }
    }
}

use std::{fmt::Debug, sync::Arc};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tower_sessions::{session, Session};

use crate::{
    backend::{AuthUser, UserId},
    AuthnBackend,
};

/// An error type which maps session and backend errors.
#[derive(thiserror::Error)]
pub enum Error<Backend: AuthnBackend> {
    /// A mapping to `tower_sessions::session::Error'.
    #[error(transparent)]
    Session(session::Error),

    /// A mapping to `Backend::Error`.
    #[error(transparent)]
    Backend(Backend::Error),
}

impl<Backend: AuthnBackend> Debug for Error<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Session(err) => write!(f, "{err:?}")?,
            Error::Backend(err) => write!(f, "{err:?}")?,
        };

        Ok(())
    }
}

impl<Backend: AuthnBackend> From<session::Error> for Error<Backend> {
    fn from(value: session::Error) -> Self {
        Self::Session(value)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Data<UserId> {
    user_id: Option<UserId>,
    auth_hash: Option<Vec<u8>>,
}

impl<UserId: Clone> Default for Data<UserId> {
    fn default() -> Self {
        Self {
            user_id: None,
            auth_hash: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Inner<Backend: AuthnBackend> {
    session: Session,
    user: Option<Backend::User>,
    data: Data<UserId<Backend>>,
    data_key: &'static str,
}

/// A specialized session for identification, authentication, and authorization
/// of users associated with a backend.
///
/// The session is generic over some backend which implements [`AuthnBackend`].
/// The backend may also implement [`AuthzBackend`](crate::AuthzBackend),
/// in which case it will also supply authorization methods.
///
/// Methods for authenticating the session and logging a user in are provided.
///
/// Generally this session will be used in the context of some authentication
/// workflow, for example via a frontend login form. There a user would provide
/// their credentials, such as username and password, and via the backend
/// the session would authenticate those credentials.
///
/// Once the supplied credentials have been authenticated, a user will be
/// returned. In the case the credentials are invalid, no user will be returned.
/// When we do have a user, it's then possible to set the state of the session
/// so that the user is logged in.
#[derive(Debug, Clone)]
pub struct AuthSession<Backend: AuthnBackend> {
    backend: Backend,
    inner: Arc<Mutex<Inner<Backend>>>,
}

impl<Backend: AuthnBackend> AuthSession<Backend> {
    /// Returns the backend associated wih his auth session.
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Returns the user that's authenicated to this session otherwise `None`.
    pub async fn user(&self) -> Option<Backend::User> {
        self.inner.lock().await.user.clone()
    }

    /// Verifies the provided credentials via the backend returning the
    /// authenticated user if valid and otherwise `None`.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn authenticate(
        &self,
        creds: Backend::Credentials,
    ) -> Result<Option<Backend::User>, Error<Backend>> {
        let result = self
            .backend
            .authenticate(creds)
            .await
            .map_err(Error::Backend);

        if let Ok(Some(ref user)) = result {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        result
    }

    /// Updates the session such that the user is logged in.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id = user.id().to_string()), ret, err)]
    pub async fn login(&mut self, user: &Backend::User) -> Result<(), Error<Backend>> {
        {
            let mut inner = self.inner.lock().await;
            inner.user = Some(user.clone());

            if inner.data.auth_hash.is_none() {
                inner.session.cycle_id().await?; // Session-fixation mitigation.
            }

            inner.data.user_id = Some(user.id());
            inner.data.auth_hash = Some(user.session_auth_hash().to_owned());
        }

        self.update_session().await?;

        Ok(())
    }

    /// Updates the session such that the user is logged out.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn logout(&mut self) -> Result<Option<Backend::User>, Error<Backend>> {
        let mut inner = self.inner.lock().await;
        let user = inner.user.take();

        if let Some(ref user) = user {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        inner.session.flush().await?;

        Ok(user)
    }

    async fn update_session(&mut self) -> Result<(), session::Error> {
        let inner = self.inner.lock().await;
        inner
            .session
            .insert(inner.data_key, inner.data.clone())
            .await
    }

    pub(crate) async fn from_session(
        session: Session,
        backend: Backend,
        data_key: &'static str,
    ) -> Result<Self, Error<Backend>> {
        let mut data: Data<_> = session.get(data_key).await?.unwrap_or_default();

        let mut user = if let Some(ref user_id) = data.user_id {
            backend.get_user(user_id).await.map_err(Error::Backend)?
        } else {
            None
        };

        if let Some(ref authed_user) = user {
            let session_auth_hash = authed_user.session_auth_hash();
            let session_verified = data
                .auth_hash
                .as_ref()
                .is_some_and(|auth_hash| auth_hash.ct_eq(session_auth_hash).into());
            if !session_verified {
                user = None;
                data = Data::default();
                session.flush().await?;
            }
        }

        let inner = Arc::new(Mutex::new(Inner {
            user,
            session,
            data,
            data_key,
        }));

        Ok(Self { backend, inner })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::{predicate::*, *};
    use tower_sessions::MemoryStore;

    use super::*;

    mock! {
        #[derive(Debug)]
        Backend {}

        impl Clone for Backend {
            fn clone(&self) -> Self;
        }

        impl AuthnBackend for Backend {
            type User = MockUser;
            type Credentials = MockCredentials;
            type Error = MockError;

            async fn authenticate(&self, creds: MockCredentials) -> Result<Option<MockUser>, MockError>;
            async fn get_user(&self, user_id: &i64) -> Result<Option<MockUser>, MockError>;

        }
    }

    #[derive(Debug, Clone)]
    struct MockUser {
        id: i64,
        auth_hash: Vec<u8>,
    }

    impl AuthUser for MockUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &self.auth_hash
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockCredentials;

    #[derive(Debug)]
    struct MockError;

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Mock error")
        }
    }

    impl std::error::Error for MockError {}

    #[tokio::test]
    async fn test_authenticate() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };
        let creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(creds.clone()))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());

        let session = Session::new(None, store, None);
        let inner = Inner {
            user: None,
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };

        let result = auth_session.authenticate(creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_authenticate_bad_credentials() {
        let mut mock_backend = MockBackend::default();
        let bad_creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(bad_creds.clone()))
            .times(1)
            .returning(|_| Ok(None));

        let store = Arc::new(MemoryStore::default());

        let session = Session::new(None, store, None);
        let inner = Inner {
            user: None,
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };
        let result = auth_session.authenticate(bad_creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_login() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        let original_session_id = session.id();
        let inner = Inner {
            user: None,
            session: session.clone(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let mut auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };

        auth_session.login(&mock_user).await.unwrap();
        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);

        // Simulate request persisting session.
        session.save().await.unwrap();

        // We were provided no session initially.
        assert!(original_session_id.is_none());

        // We have a session ID after saving.
        assert!(session.id().is_some());
    }

    #[tokio::test]
    async fn test_logout() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        let inner = Inner {
            user: Some(mock_user),
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let mut auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };
        let logged_out_user = auth_session.logout().await.unwrap();
        assert!(logged_out_user.is_some());
        assert_eq!(logged_out_user.unwrap().id(), 42);
        assert!(auth_session.user().await.is_none());
    }

    #[tokio::test]
    async fn test_from_session() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store.clone(), None);
        let data_key = "auth_data";

        // Simulate a user being logged in
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![1, 2, 3, 4]),
        };
        session.insert(data_key, &data).await.unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);
    }

    #[tokio::test]
    async fn test_from_session_bad_auth_hash() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store.clone(), None);
        let data_key = "auth_data";

        // Try to use a malformed auth hash.
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![4, 3, 2, 1]),
        };
        session.insert(data_key, &data).await.unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_none());
    }
}

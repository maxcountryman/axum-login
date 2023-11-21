
use std::fmt::Debug;
//use ring::constant_time::verify_slices_are_equal;
use serde::{Deserialize, Serialize};
use tower_sessions::{session, Session};

use crate::{
    backend::{AuthUser, UserId},
    AuthnBackend,
};

fn compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    for (ai, bi) in a.iter().zip(b.iter()) {
        match ai.cmp(bi) {
            core::cmp::Ordering::Equal => continue,
            ord => return ord
        }
    }

    /* if every single element was equal, compare length */
    a.len().cmp(&b.len())
}


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
            Error::Session(err) => write!(f, "{:?}", err)?,
            Error::Backend(err) => write!(f, "{:?}", err)?,
        };

        Ok(())
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
    /// The user associated by the backend. `None` when not logged in.
    pub user: Option<Backend::User>,

    /// The authentication and authorization backend.
    pub backend: Backend,

    data: Data<UserId<Backend>>,
    session: Session,
    data_key: &'static str,
}

impl<Backend: AuthnBackend> AuthSession<Backend> {
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
        self.user = Some(user.clone());

        if self.data.auth_hash.is_none() {
            self.session.cycle_id(); // Session-fixation mitigation.
        }

        self.data.user_id = Some(user.id());
        self.data.auth_hash = Some(user.session_auth_hash().to_owned());

        self.update_session().map_err(Error::Session)?;

        Ok(())
    }

    /// Updates the session such that the user is logged out.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub fn logout(&mut self) -> Result<Option<Backend::User>, Error<Backend>> {
        let user = self.user.clone();

        if let Some(ref user) = user {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        self.user = None;
        self.data = Data::default();
        self.session.flush();

        self.update_session().map_err(Error::Session)?;

        Ok(user)
    }

    fn update_session(&mut self) -> Result<(), session::Error> {
        self.session.insert(self.data_key, self.data.clone())
    }

    pub(crate) async fn from_session(
        session: Session,
        backend: Backend,
        data_key: &'static str,
    ) -> Result<Self, Error<Backend>> {
        let mut data: Data<_> = session
            .get(data_key)
            .map_err(Error::Session)?
            .unwrap_or_default();

        let mut user = if let Some(ref user_id) = data.user_id {
            backend.get_user(user_id).await.map_err(Error::Backend)?
        } else {
            None
        };

        if let Some(ref authed_user) = user {
            let session_auth_hash = authed_user.session_auth_hash();
            let session_verified = &data.auth_hash.clone().is_some_and(|auth_hash| {
                //verify_slices_are_equal(&auth_hash[..], session_auth_hash).is_ok()
                compare(&auth_hash[..],session_auth_hash) == core::cmp::Ordering::Equal
            });
            if !session_verified {
                user = None;
                data = Data::default();
                session.flush();
            }
        }

        Ok(Self {
            user,
            data,
            backend,
            session,
            data_key,
        })
    }
}

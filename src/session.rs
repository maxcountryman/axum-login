use std::fmt::Debug;

use http::Request;
use ring::constant_time::verify_slices_are_equal;
use serde::{Deserialize, Serialize};
use tower_sessions::{session, Session};

use crate::{
    backend::{AuthUser, UserId},
    AuthBackend,
};

/// An error type to map session and access controller errors.
#[derive(thiserror::Error)]
pub enum Error<Backend: AuthBackend> {
    #[error(transparent)]
    Session(session::Error),

    #[error(transparent)]
    Backend(Backend::Error),
}

impl<Backend: AuthBackend> Debug for Error<Backend> {
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

#[derive(Clone)]
pub struct AuthSession<Backend: AuthBackend> {
    pub user: Option<Backend::User>,
    pub backend: Backend,

    data: Data<UserId<Backend>>,
    session: Session,
}

impl<Backend: AuthBackend> AuthSession<Backend> {
    const DATA_KEY: &'static str = "axum-login.data";

    pub async fn authenticate(
        &self,
        creds: Backend::Credentials,
    ) -> Result<Option<Backend::User>, Error<Backend>> {
        Ok(self
            .backend
            .authenticate(creds)
            .await
            .map_err(Error::Backend)?)
    }

    pub async fn login(&mut self, user: &Backend::User) -> Result<(), Error<Backend>> {
        self.user = Some(user.clone());
        self.data.user_id = Some(user.id());
        self.data.auth_hash = Some(user.session_auth_hash());
        self.session.cycle_id(); // Session-fixation mitigation.

        self.update_session().map_err(Error::Session)?;

        Ok(())
    }

    pub fn logout(&mut self) -> Result<Option<Backend::User>, Error<Backend>> {
        self.user = None;
        self.data = Data::default();
        self.session.flush();

        self.update_session().map_err(Error::Session)?;

        Ok(self.user.clone())
    }

    fn update_session(&mut self) -> Result<(), session::Error> {
        self.session.insert(Self::DATA_KEY, self.data.clone())
    }

    pub(crate) async fn from_session(
        session: Session,
        backend: Backend,
    ) -> Result<Self, Error<Backend>> {
        let mut data: Data<_> = session
            .get(Self::DATA_KEY)
            .map_err(Error::Session)?
            .unwrap_or_default();

        let mut user = if let Some(ref user_id) = data.user_id {
            backend.get_user(user_id).await.map_err(Error::Backend)?
        } else {
            None
        };

        let session_verified = data
            .auth_hash
            .clone()
            .and_then(|user_hash| {
                verify_slices_are_equal(&user_hash[..], &user.clone()?.session_auth_hash()).ok()
            })
            .is_some();

        if !session_verified {
            user = None;
            data = Data::default();
            session.flush();
        }

        Ok(Self {
            user,
            data,
            backend,
            session,
        })
    }
}

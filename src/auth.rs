//! An authentication context which provides methods for logging users in and
//! out.
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use tower_sessions::{session::SessionError, Session};

use crate::UserStore;

/// An error type to map session and user store errors.
#[derive(thiserror::Error)]
pub enum AuthError<Users: UserStore> {
    #[error(transparent)]
    Session(SessionError),

    #[error(transparent)]
    Users(Users::Error),
}

impl<Users: UserStore> Debug for AuthError<Users> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Session(err) => write!(f, "{:?}", err)?,
            AuthError::Users(err) => write!(f, "{:?}", err)?,
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthData<UserId> {
    user_id: Option<UserId>,
}

impl<UserId> Default for AuthData<UserId>
where
    UserId: Clone,
{
    fn default() -> Self {
        Self { user_id: None }
    }
}

/// An authentication context which provides methods for logging users in and
/// out.
///
/// This manages the authentication state for a user. The user and user store
/// are directly accessible via this type.
///
/// Note that the user will be `None` when the user is logged out.
#[derive(Debug, Clone)]
pub struct Auth<Users: UserStore> {
    pub user: Option<Users::User>,
    pub user_store: Users,
    auth_data: AuthData<Users::UserId>,
    session: Session,
}

impl<Users: UserStore> Auth<Users> {
    const AUTH_DATA_KEY: &'static str = "axum-login/auth-data";

    /// Given some user ID, sets the session state such that they are logged in.
    pub async fn login(
        &mut self,
        user_id: &Users::UserId,
    ) -> Result<Option<Users::User>, AuthError<Users>> {
        if let Some(user) = self
            .user_store
            .load(user_id)
            .await
            .map_err(AuthError::Users)?
        {
            self.user = Some(user);
            self.session.cycle_id(); // Session-fixation mitigation.
            self.auth_data.user_id = Some(user_id.clone());
            self.update_session().map_err(AuthError::Session)?;
        };

        Ok(self.user.clone())
    }

    /// Logs a user out by flushing the session and reseting authentication data
    /// to its default.
    pub fn logout(&mut self) -> Result<Option<Users::User>, AuthError<Users>> {
        self.session.flush();
        self.auth_data = AuthData::default();
        self.update_session().map_err(AuthError::Session)?;

        Ok(self.user.clone())
    }

    fn update_session(&mut self) -> Result<(), SessionError> {
        self.session
            .insert(Self::AUTH_DATA_KEY, self.auth_data.clone())
    }

    pub(crate) async fn from_session(
        session: Session,
        user_store: Users,
    ) -> Result<Self, AuthError<Users>> {
        let auth_data: AuthData<_> = session
            .get(Self::AUTH_DATA_KEY)
            .map_err(AuthError::Session)?
            .unwrap_or_default();

        let user = if let Some(ref user_id) = auth_data.user_id {
            user_store.load(user_id).await.map_err(AuthError::Users)?
        } else {
            None
        };

        Ok(Self {
            user,
            auth_data,
            user_store,
            session,
        })
    }
}

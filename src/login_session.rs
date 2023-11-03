use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use tower_sessions::{session, Session};

use crate::AccessController;

/// An error type to map session and access controller errors.
#[derive(thiserror::Error)]
pub enum Error<Controller: AccessController> {
    #[error(transparent)]
    Session(session::Error),

    #[error(transparent)]
    Users(Controller::Error),
}

impl<Controller: AccessController> Debug for Error<Controller> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Session(err) => write!(f, "{:?}", err)?,
            Error::Users(err) => write!(f, "{:?}", err)?,
        };

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Data<UserId> {
    user_id: Option<UserId>,
}

impl<UserId> Default for Data<UserId>
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
pub struct LoginSession<Controller: AccessController> {
    /// The logged in user, if there is one. Otherwise `None`.
    pub user: Option<Controller::User>,

    /// The user access controller.
    pub access_controller: Controller,

    data: Data<Controller::UserId>,
    session: Session,
}

impl<Controller: AccessController> LoginSession<Controller> {
    const DATA_KEY: &'static str = "axum-login.data";

    /// Given some user ID, sets the session state such that they are logged in.
    pub async fn login(
        &mut self,
        user_id: &Controller::UserId,
    ) -> Result<Option<Controller::User>, Error<Controller>> {
        if let Some(user) = self
            .access_controller
            .load_user(user_id)
            .await
            .map_err(Error::Users)?
        {
            self.user = Some(user);
            self.session.cycle_id(); // Session-fixation mitigation.
            self.data.user_id = Some(user_id.clone());
            self.update_session().map_err(Error::Session)?;
        };

        Ok(self.user.clone())
    }

    /// Logs a user out by flushing the session and reseting authentication data
    /// to its default.
    pub fn logout(&mut self) -> Result<Option<Controller::User>, Error<Controller>> {
        self.session.flush();
        self.data = Data::default();
        self.update_session().map_err(Error::Session)?;

        Ok(self.user.clone())
    }

    fn update_session(&mut self) -> Result<(), session::Error> {
        // N.B. We aren't concerned about atomic updates here because our writes are not
        // based on read values from the session.
        self.session.insert(Self::DATA_KEY, self.data.clone())
    }

    pub(crate) async fn from_session(
        session: Session,
        access_controller: Controller,
    ) -> Result<Self, Error<Controller>> {
        let auth_data: Data<_> = session
            .get(Self::DATA_KEY)
            .map_err(Error::Session)?
            .unwrap_or_default();

        let user = if let Some(ref user_id) = auth_data.user_id {
            access_controller
                .load_user(user_id)
                .await
                .map_err(Error::Users)?
        } else {
            None
        };

        Ok(Self {
            user,
            data: auth_data,
            access_controller,
            session,
        })
    }
}

//! Axum extractors providing authentication methods.

use std::marker::PhantomData;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts, Extension};
use axum_sessions::SessionHandle;
use ring::hmac::{self, Key};
use secrecy::ExposeSecret;
use serde::{de::DeserializeOwned, Serialize};

use crate::{user_store::UserStore, AuthUser};

const SESSION_AUTH_ID_KEY: &str = "_auth_id";
const SESSION_USER_ID_KEY: &str = "_user_id";

/// An extractor which provides the auth context.
///
/// This may be used to access the current user, log a given user in or log the
/// current user out. Note that when no user is logged in the value of
/// `current_user` will be `None`.
///
/// The logged in state is managed via the presence of two session key-value
/// pairs:
///
/// 1. Auth ID, which is an HMAC SHA512 signature of the user password hash,
/// 2. User ID, which is some unique ID belonging to the user.
///
/// Session validity is checked upon user access, meaning that if a password
/// hash should change, a session will become invalidated and a user will need
/// to reauthenticate. The exact semantics of this may be controlled via the
/// implementation of
/// [`get_password_hash`](crate::auth_user::AuthUser::get_password_hash).
///
/// Assumes the extractor is used only after the auth layer has been installed.
#[derive(Debug, Clone)]
pub struct AuthContext<UserId, User, Store, Role = ()> {
    /// The currently logged in user for the session, if any.
    pub current_user: Option<User>,
    session_handle: SessionHandle,
    store: Store,
    key: Key,
    _user_id: PhantomData<UserId>,
    _role: PhantomData<Role>,
}

impl<UserId, User, Store, Role> AuthContext<UserId, User, Store, Role>
where
    UserId: Serialize + DeserializeOwned,
    User: AuthUser<UserId, Role>,
    Store: UserStore<UserId, Role, User = User>,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    fn get_session_auth_id(&self, password_hash: &[u8]) -> String {
        let tag = hmac::sign(&self.key, password_hash);
        base64::encode(tag.as_ref())
    }

    pub(super) fn new(session_handle: SessionHandle, store: Store, key: Key) -> Self {
        Self {
            current_user: None,
            session_handle,
            store,
            key,
            _user_id: PhantomData,
            _role: PhantomData,
        }
    }

    pub(super) async fn get_user(&mut self) -> crate::Result<Option<User>> {
        let session = self.session_handle.read().await;

        if let Some(user_id) = session.get::<UserId>(SESSION_USER_ID_KEY) {
            if let Some(user) = self.store.load_user(&user_id).await? {
                let session_auth_id = session
                    .get::<String>(SESSION_AUTH_ID_KEY)
                    .and_then(|auth_id| base64::decode(auth_id).ok())
                    .unwrap_or_default();
                drop(session);

                let password_hash = user.get_password_hash();
                let data = password_hash.expose_secret();

                if hmac::verify(&self.key, data, &session_auth_id).is_ok() {
                    return Ok(Some(user));
                } else {
                    self.logout().await;
                }
            }
        }

        Ok(None)
    }

    /// Authenticates the session with the given user.
    ///
    /// A signed session ID will be generated from the value of
    /// [`get_password_hash`](crate::auth_user::AuthUser::get_password_hash) and
    /// the value of [`get_id`](crate::auth_user::AuthUser::get_id) will be used
    /// to identify the user on future requests. Once the session has been
    /// updated, the `current_user` will be set to provided user.
    pub async fn login(&mut self, user: &User) -> crate::Result<()> {
        let auth_id = self.get_session_auth_id(user.get_password_hash().expose_secret());
        let user_id = user.get_id();

        let mut session = self.session_handle.write().await;
        session.insert(SESSION_AUTH_ID_KEY, auth_id)?;
        session.insert(SESSION_USER_ID_KEY, user_id)?;

        self.current_user = Some(user.clone());

        Ok(())
    }

    /// Destroys the session entirely.
    ///
    /// Subsequent requests will not provide an authenticated session until
    /// `login` is invoked again.
    pub async fn logout(&mut self) {
        let mut session = self.session_handle.write().await;
        session.destroy();
    }
}

#[async_trait]
impl<State, UserId, User, Store, Role> FromRequestParts<State>
    for AuthContext<UserId, User, Store, Role>
where
    UserId: Clone + Send + Sync + 'static,
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
    State: Send + Sync,
    User: AuthUser<UserId, Role>,
    Store: UserStore<UserId, Role, User = User>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &State) -> Result<Self, Self::Rejection> {
        let Extension(auth_cx): Extension<AuthContext<_, _, _, _>> =
            Extension::from_request_parts(parts, state)
                .await
                .expect("Auth extension missing. Is the auth layer installed?");

        Ok(auth_cx)
    }
}

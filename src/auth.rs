use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    middleware::Next,
    response::Response,
};
use http::{request::Parts, Request, StatusCode};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::{auth_state::AuthState, user_store::UserStore};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthData<UserId> {
    user_id: Option<UserId>,
}

impl<UserId> Default for AuthData<UserId> {
    fn default() -> Self {
        Self { user_id: None }
    }
}

#[derive(Debug)]
pub struct Auth<User, UserId, Store>
where
    Store: UserStore<User, UserId>,
{
    pub user: Option<User>,
    auth_data: AuthData<UserId>,
    user_store: Store,
    session: Session,
}

impl<User, UserId, Store> Auth<User, UserId, Store>
where
    User: Clone + Serialize + for<'a> Deserialize<'a>,
    UserId: Clone + Serialize + for<'a> Deserialize<'a>,
    Store: UserStore<User, UserId>,
{
    const AUTH_DATA_KEY: &'static str = "axum-login.auth-data";

    pub async fn login(&mut self, user_id: &UserId) -> Result<(), Store::Error> {
        if let Some(user) = self.user_store.load(user_id).await? {
            self.user = Some(user);
            self.auth_data.user_id = Some(user_id.clone());
            self.session.cycle_id(); // Session-fixation mitigation.
            self.update_session();
        };
        Ok(())
    }

    pub fn logout(&mut self) {
        self.session
            .remove::<AuthData<UserId>>(Self::AUTH_DATA_KEY)
            .expect("infallible");
        self.auth_data = AuthData::default();
        self.update_session();
    }

    fn update_session(&self) {
        self.session
            .insert(Self::AUTH_DATA_KEY, self.auth_data.clone())
            .expect("infallible")
    }
}

#[async_trait]
impl<S, User, UserId, Store> FromRequestParts<S> for Auth<User, UserId, Store>
where
    S: Send + Sync,
    User: Clone + Serialize + for<'a> Deserialize<'a>,
    UserId: Clone + Send + Sync + Serialize + for<'a> Deserialize<'a>,
    Store: UserStore<User, UserId>,
    AuthState<User, UserId, Store>: FromRef<S>,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;

        let auth_data: AuthData<_> = session
            .get(Self::AUTH_DATA_KEY)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ""))?
            .unwrap_or_default();

        let AuthState { user_store, .. } = AuthState::from_ref(state);

        // Poll store to refresh current user.
        let user = if let Some(ref user_id) = auth_data.user_id {
            match user_store.load(user_id).await {
                Ok(user) => user,

                Err(_) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Could not load from user store. Is the store online?",
                    ))
                }
            }
        } else {
            None
        };

        Ok(Auth {
            user,
            auth_data,
            user_store,
            session,
        })
    }
}

pub async fn require_auth<User, UserId, Store, B>(
    auth: Auth<User, UserId, Store>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode>
where
    Store: UserStore<User, UserId>,
{
    if auth.user.is_some() {
        let res = next.run(req).await;
        Ok(res)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

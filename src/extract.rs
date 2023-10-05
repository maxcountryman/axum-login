use async_trait::async_trait;
use axum::extract::FromRequestParts;
use serde::{Deserialize, Serialize};

#[async_trait]
impl<S, User, UserId, Store> FromRequestParts<S> for Auth<User, UserId, Store>
where
    S: Send + Sync,
    User: Serialize + for<'a> Deserialize<'a> + Clone + Send,
    UserId: Serialize + for<'a> Deserialize<'a> + Clone + Send + Sync,
    Store: UserStore<User, UserId> + Send + Sync,
    AuthState<User, UserId, Store>: FromRef<S>,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;

        let mut auth_data: AuthData<User, UserId> = session
            .get(Self::AUTH_DATA_KEY)
            .expect("infallible")
            .unwrap_or(AuthData {
                user: None,
                user_id: None,
            });

        let AuthState { user_store, .. } = AuthState::from_ref(state);

        // Poll store to refresh current user.
        if let Some(ref user_id) = auth_data.user_id {
            match user_store.load(user_id).await {
                Ok(user) => auth_data.user = user,

                Err(_) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Could not load from user store. Is the store online?",
                    ))
                }
            }
        };

        Ok(Auth {
            session,
            auth_data,
            user_store,
        })
    }
}

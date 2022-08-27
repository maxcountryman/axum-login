use std::marker::PhantomData;

use axum::{
    body::HttpBody,
    http::{self, Request, Response},
};
use tower_http::auth::AuthorizeRequest;

use crate::AuthUser;

pub struct Login<User, ResBody> {
    _user_type: PhantomData<User>,
    _body_type: PhantomData<fn() -> ResBody>,
}

impl<User, ResBody> Clone for Login<User, ResBody> {
    fn clone(&self) -> Self {
        Self {
            _user_type: PhantomData,
            _body_type: PhantomData,
        }
    }
}

impl<User, B, ResBody> AuthorizeRequest<B> for Login<User, ResBody>
where
    User: AuthUser,
    ResBody: HttpBody + Default,
{
    type ResponseBody = ResBody;

    fn authorize(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        let user = request.extensions().get::<Option<User>>();
        if let Some(Some(user)) = user {
            let user = user.clone();
            request.extensions_mut().insert(user);

            Ok(())
        } else {
            let unauthorized_response = Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(Default::default())
                .unwrap();

            Err(unauthorized_response)
        }
    }
}

pub struct RequireAuthorizationLayer;

impl RequireAuthorizationLayer {
    pub fn login<User, ResBody>(
    ) -> tower_http::auth::RequireAuthorizationLayer<Login<User, ResBody>>
    where
        User: AuthUser,
        ResBody: HttpBody + Default,
    {
        tower_http::auth::RequireAuthorizationLayer::custom(Login::<_, _> {
            _user_type: PhantomData,
            _body_type: PhantomData,
        })
    }
}

use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct AuthState<User, UserId, Store> {
    pub user_store: Store,
    _user: PhantomData<User>,
    _user_id: PhantomData<UserId>,
}

impl<User, UserId, Store> AuthState<User, UserId, Store> {
    pub fn new(user_store: Store) -> Self {
        Self {
            user_store,
            _user: PhantomData,
            _user_id: PhantomData,
        }
    }
}

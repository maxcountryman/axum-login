/// A trait which defines methods that allow an arbitrary user type to be
/// authenticated.
///
/// This trait must be implemented for arbitrary user types which wish to
/// participate in the authentication process.
pub trait AuthUser: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// Returns the ID of the user.
    ///
    /// This is used to generate the user ID for the session. We assume this
    /// value is globally unique and will not change.
    fn get_id(&self) -> String;

    /// Returns the password hash of the user.
    ///
    /// This is used to generate a unique auth ID for the session. Note that a
    /// password hash changing will cause the session to become invalidated.
    fn get_password_hash(&self) -> String;
}

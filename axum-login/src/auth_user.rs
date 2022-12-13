/// A trait which defines methods that allow an arbitrary user type to be
/// authenticated.
///
/// This trait must be implemented for arbitrary user types which wish to
/// participate in the authentication process.
///
/// As an example, we might implement the trait for a custom user type,
/// `MyUser`, like so:
///
/// ```rust
/// use axum_login::AuthUser;
/// use secrecy::{ExposeSecret, SecretVec};
///
/// #[derive(Debug, Clone)]
/// struct MyUser {
///     id: i64,
///     name: String,
///     password_hash: String,
/// }
///
/// #[derive(Debug, Clone, PartialEq, PartialOrd)]
/// enum Role {
///     User,
///     Admin,
/// }
///
/// impl AuthUser<Role> for MyUser {
///     fn get_id(&self) -> String {
///         format!("{}", self.id)
///     }
///
///     fn get_password_hash(&self) -> SecretVec<u8> {
///         SecretVec::new(self.password_hash.clone().into())
///     }
/// }
///
/// # fn main() {
/// let user = MyUser {
///     id: 1,
///     name: "Ferris the Crab".to_string(),
///     password_hash: "hunter42".to_string(),
/// };
///
/// assert_eq!(user.get_id(), "1".to_string());
/// assert_eq!(
///     user.get_password_hash().expose_secret(),
///     SecretVec::new("hunter42".into()).expose_secret()
/// );
/// # }
/// ```
pub trait AuthUser<Role = ()>: Clone + Send + Sync + 'static
where
    Role: PartialOrd + PartialEq + Clone + Send + Sync + 'static,
{
    /// Returns the ID of the user.
    ///
    /// This is used to generate the user ID for the session. We assume this
    /// value is globally unique and will not change.
    fn get_id(&self) -> String;

    /// Returns the password hash of the user.
    ///
    /// This is used to generate a unique auth ID for the session. Note that a
    /// password hash changing will cause the session to become invalidated.
    fn get_password_hash(&self) -> secrecy::SecretVec<u8>;

    /// Returns the role assigned to the given user.
    ///
    /// This is used when specifying role requirements for handlers.
    fn get_role(&self) -> Option<Role> {
        None
    }
}

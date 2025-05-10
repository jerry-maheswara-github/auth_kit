use crate::error::AuthError;
use crate::model::{Role, User};
use std::collections::HashMap;

/// A basic in-memory authentication service.
///
/// This struct manages users, supports registration, login, and password reset
/// with optional token verification.
#[derive(Debug)]
pub struct Authentication {
    /// A map of user email to `User` object.
    pub users: HashMap<String, User>,
}

impl Authentication {
    /// Creates a new, empty `Authentication` instance.
    ///
    /// # Example
    /// ```code
    /// let auth = Authentication::new();
    /// ```
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    /// Registers a new user by email and hashed password.
    ///
    /// # Arguments
    /// * `email` - The email address of the new user.
    /// * `password_hash` - The hashed password to store.
    ///
    /// # Returns
    /// * `Ok(())` if registration was successful.
    /// * `Err(AuthError::EmailAlreadyRegistered)` if the email is already in use.
    ///
    /// # Example
    /// ```code
    /// auth.register("user@example.com", "hashed_password")?;
    /// ```
    pub fn register(&mut self, email: &str, password_hash: &str) -> Result<(), AuthError> {
        if self.users.contains_key(email) {
            return Err(AuthError::EmailAlreadyRegistered);
        }

        let user = User {
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            role: Role { name: "".to_string(), permissions: vec![] },
            department: "".to_string(),
            clearance_level: 0,
        };

        self.users.insert(email.to_string(), user);
        Ok(())
    }

    /// Attempts to log in a user by email.
    ///
    /// # Arguments
    /// * `email` - The email address to look up.
    ///
    /// # Returns
    /// * `Ok(Some(User))` if the user exists.
    /// * `Err(AuthError::UserNotFound)` if the user does not exist.
    ///
    /// # Example
    /// ```code
    /// let user = auth.login("user@example.com")?;
    /// ```
    pub fn login(&self, email: &str) -> Result<Option<User>, AuthError> {
        match self.users.get(email) {
            Some(user) => Ok(Some(user.clone())),
            None => Err(AuthError::UserNotFound),
        }
    }

    /// Resets a user's password, validating a token before allowing the change.
    ///
    /// # Arguments
    /// * `email` - The email address of the user.
    /// * `token` - The reset token to validate.
    /// * `new_password_hash` - The new hashed password to set.
    /// * `verify_token` - A function to verify the validity of the token.
    ///
    /// # Returns
    /// * `Ok(())` if the password was successfully reset.
    /// * `Err(AuthError::InvalidToken)` if the token is invalid.
    /// * `Err(AuthError::UserNotFound)` if the user does not exist.
    ///
    /// # Example
    /// ```code
    /// auth.reset_password("user@example.com", "reset_token", "new_hashed_pw", |t| t == "reset_token")?;
    /// ```
    pub fn reset_password<F>(&mut self, email: &str, token: &str, new_password_hash: &str, verify_token: F) -> Result<(), AuthError>
    where
        F: Fn(&str) -> bool,
    {
        match self.users.get_mut(email) {
            Some(user) => {
                if !verify_token(token) {
                    return Err(AuthError::InvalidToken);
                }

                user.password_hash = new_password_hash.to_string();
                Ok(())
            }
            None => Err(AuthError::UserNotFound),
        }
    }
}

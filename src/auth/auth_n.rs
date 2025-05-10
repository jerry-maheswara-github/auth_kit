use crate::error::AuthError;
use crate::model::{Role, User};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Authentication {
    pub users: HashMap<String, User>,
}

impl Authentication {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }


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

    pub fn login(&self, email: &str) -> Result<Option<User>, AuthError> {
        match self.users.get(email) {
            Some(user) => Ok(Some(user.clone())),
            None => Err(AuthError::UserNotFound),
        }
    }

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

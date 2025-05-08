use bcrypt::{hash, verify, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::AuthError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug)]
pub struct Authenticator {
    users: HashMap<String, User>,
}

impl Authenticator {
    pub fn new() -> Self {
        Authenticator {
            users: HashMap::new(),
        }
    }

    pub fn register(&mut self, email: &str, password: &str) -> Result<(), AuthError> {
        if self.users.contains_key(email) {
            return Err(AuthError::EmailAlreadyRegistered);
        }

        let password_hash = hash(password, DEFAULT_COST)
            .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;

        let user = User {
            email: email.to_string(),
            password_hash,
        };

        self.users.insert(email.to_string(), user);
        Ok(())
    }

    pub fn login(&self, email: &str, password: &str) -> Result<Option<User>, AuthError> {
        match self.users.get(email) {
            Some(user) => {
                let is_valid = verify(password, &user.password_hash)
                    .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;

                if is_valid {
                    Ok(Some(user.clone()))
                } else {
                    Err(AuthError::InvalidPassword)
                }
            }
            None => Err(AuthError::UserNotFound),
        }
    }

    pub fn reset_password<F>(&mut self, email: &str, token: &str, new_password: &str, verify_token: F) -> Result<(), AuthError>
    where
        F: Fn(&str) -> bool,
    {
        match self.users.get_mut(email) {
            Some(user) => {
                if !verify_token(token) {
                    return Err(AuthError::InvalidToken);
                }

                let password_hash = hash(new_password, DEFAULT_COST)
                    .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;
                user.password_hash = password_hash;
                Ok(())
            }
            None => Err(AuthError::UserNotFound),
        }
    }

    pub fn authorize<F>(
        &self,
        user: &User,
        service: &str,
        permission: &str,
        check_permission: F,
    ) -> Result<(), AuthError>
    where
        F: Fn(&User, &str, &str) -> bool,
    {
        if check_permission(user, service, permission) {
            Ok(())
        } else {
            Err(AuthError::AccessDenied {
                service: service.to_string(),
                permission: permission.to_string(),
            })
        }
    }
}

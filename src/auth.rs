use std::collections::HashMap;
use std::fmt;
use serde::Deserialize;
use crate::error::AuthError;

#[derive(Debug, Clone)]
pub struct User {
    pub email: String,
    pub password_hash: String,
    pub role: Role,
    pub department: String,
    pub clearance_level: u8,
}

pub trait Identifiable {
    fn identity(&self) -> String;
}

impl Identifiable for User {
    fn identity(&self) -> String {
        self.email.clone()
    }
}

impl Identifiable for Claims {
    fn identity(&self) -> String {
        self.email.clone()
    }
}

pub enum AuthStrategy {
    RBAC,
    JWT,
    ABAC,
}

pub struct AuthContext<'a> {
    pub user: Option<&'a User>,
    pub claims: Option<&'a Claims>,
    pub resource: Option<&'a Resource>,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub email: String,
    pub service: String,
    pub scopes: Vec<String>,
}

#[derive(Debug)]
pub struct Resource {
    pub department: String,
    pub required_level: u8,
}

#[derive(Debug)]
pub struct Authenticator {
    pub users: HashMap<String, User>,
}

#[derive(Debug, Clone)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Permission {
    Create,
    Read,
    Update,
    Delete,
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Permission::Create => "create",
            Permission::Read => "read",
            Permission::Update => "update",
            Permission::Delete => "delete",
        };
        write!(f, "{}", s)
    }
}

impl Authenticator {
    pub fn new() -> Self {
        Authenticator {
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

    pub fn authorize_with_strategy(
        &mut self,
        context: &AuthContext,
        strategy: AuthStrategy,
        service: &str,
        permission: &str,
    ) -> Result<(), AuthError> {
        match strategy {
            AuthStrategy::RBAC => {
                let user = context.user.ok_or(AuthError::MissingUser)?;
                authorize(user, service, permission, |u, _, p| {
                    u.role.permissions.iter().any(|perm| format!("{:?}", perm).eq_ignore_ascii_case(p))
                })
            }

            AuthStrategy::JWT => {
                let claims = context.claims.ok_or(AuthError::MissingClaims)?;
                authorize(claims, service, permission, |c, s, p| {
                    let scope = format!("{}:{}", s, p);
                    c.scopes.contains(&scope)
                })
            }

            AuthStrategy::ABAC => {
                let user = context.user.ok_or(AuthError::MissingUser)?;
                let resource = context.resource.ok_or(AuthError::MissingResource)?;
                authorize(user, service, permission, |u, _, _| {
                    u.department == resource.department && u.clearance_level >= resource.required_level
                })
            }
        }
    }


}

pub fn authorize<U, S, P, F>(
    user: &U,
    service: S,
    permission: P,
    check_permission: F,
) -> Result<(), AuthError>
where
    F: Fn(&U, &S, &P) -> bool,
    U: Identifiable,
    S: ToString,
    P: ToString,
{
    if check_permission(user, &service, &permission) {
        Ok(())
    } else {
        Err(AuthError::AccessDenied {
            user: user.identity(),
            service: service.to_string(),
            permission: permission.to_string(),
        })
    }
}

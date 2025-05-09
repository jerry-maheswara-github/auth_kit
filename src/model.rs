use std::fmt;
use serde::Deserialize;

#[derive(Debug)]
pub enum AuthStrategy {
    RBAC,
    JWT,
    ABAC,
}

impl AuthStrategy {
    pub fn from_str(strategy: &str) -> Result<Self, &'static str> {
        match strategy.to_uppercase().as_str() {
            "RBAC" => Ok(AuthStrategy::RBAC),
            "JWT" => Ok(AuthStrategy::JWT),
            "ABAC" => Ok(AuthStrategy::ABAC),
            _ => Err("Invalid strategy"),
        }
    }
}

pub struct AuthContext<'a> {
    pub user: Option<&'a User>,
    pub claims: Option<&'a Claims>,
    pub resource: Option<&'a Resource>,
}


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

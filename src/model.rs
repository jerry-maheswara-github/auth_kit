use std::fmt;
use serde::Deserialize;
use crate::error::AuthError;

/// Defines supported authorization strategies.
#[derive(Debug)]
pub enum AuthStrategy {
    /// Attribute-Based Access Control.
    ABAC,
    /// Role-Based Access Control.
    RBAC,
    /// Scope-Based Authorization (commonly used with OAuth2).
    SBA,
}

impl AuthStrategy {
    /// Parses a string into an `AuthStrategy`.
    ///
    /// # Arguments
    ///
    /// * `strategy` - A case-insensitive string representing the strategy.
    ///
    /// # Returns
    ///
    /// A `Result` containing the matching `AuthStrategy` or an error string if invalid.
    pub fn from_str(strategy: &str) -> Result<Self, AuthError> {
        match strategy.to_uppercase().as_str() {
            "ABAC" => Ok(AuthStrategy::ABAC),
            "RBAC" => Ok(AuthStrategy::RBAC),
            "SBA" => Ok(AuthStrategy::SBA),
            _ => Err(AuthError::InvalidStrategy(strategy.to_string())),
        }
    }
}

/// Represents the authentication and authorization context used for policy decisions.
pub struct AuthContext {
    /// Optional authenticated user.
    pub user: Option<User>,
    /// Optional claims typically extracted from a token.
    pub claims: Option<Claims>,
    /// Optional resource being accessed.
    pub resource: Option<Resource>,
}

/// Represents a user in the system.
#[derive(Debug, Clone)]
pub struct User {
    /// User's email address (also serves as identity).
    pub email: String,
    /// Password hash (not used directly in authorization logic).
    pub password_hash: String,
    /// Role assigned to the user.
    pub role: Role,
    /// Department to which the user belongs.
    pub department: String,
    /// Clearance level of the user.
    pub clearance_level: u8,
}

/// A trait for any type that can be identified in audit or authorization logs.
pub trait Identifiable {
    /// Returns a string identifier (e.g. email).
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

/// Represents claims typically extracted from a JWT or OAuth2 token.
#[derive(Debug, Deserialize, Clone)]
pub struct Claims {
    /// Email address associated with the token.
    pub email: String,
    /// Service name the token is scoped for.
    pub service: String,
    /// A list of scope strings representing granted permissions.
    pub scopes: Vec<String>,
}

/// Represents a resource that may require access control.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Department the resource belongs to.
    pub department: String,
    /// Required clearance level to access the resource.
    pub required_level: u8,
}

/// Represents a role assigned to users, containing named permissions.
#[derive(Debug, Clone)]
pub struct Role {
    /// Name of the role (e.g. "admin", "editor").
    pub name: String,
    /// A list of permissions granted to this role.
    pub permissions: Vec<Permission>,
}

/// Enumerates the types of actions that may be authorized.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Permission {
    /// Create permission.
    Create,
    /// Read permission.
    Read,
    /// Update permission.
    Update,
    /// Delete permission.
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

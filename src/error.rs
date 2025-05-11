use thiserror::Error;

/// Represents all possible errors that can occur during authentication and authorization.
#[derive(Error, Debug, PartialEq)]
pub enum AuthError {
    /// Occurs when the user record cannot be found in the data source.
    #[error("User not found")]
    UserNotFound,

    /// Occurs when the provided password does not match the stored hash.
    #[error("Invalid password")]
    InvalidPassword,

    /// Occurs when trying to register an email that already exists in the system.
    #[error("Email is already registered")]
    EmailAlreadyRegistered,

    /// Occurs when the authentication token is missing, malformed, or expired.
    #[error("Invalid or expired token")]
    InvalidToken,

    /// Occurs when the user lacks the required permission to access a specific service.
    #[error("Access denied to user '{user}' for service '{service}' with permission '{permission}'")]
    AccessDenied {
        /// The identifier of the user who attempted access.
        user: String,
        /// The name of the service the user attempted to access.
        service: String,
        /// The permission required to access the service.
        permission: String,
    },

    /// Occurs when password hashing fails due to an internal error.
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),

    /// Occurs when a user is missing from the authorization context.
    #[error("Missing user in context")]
    MissingUser,

    /// Occurs when claims are missing from the authorization context.
    #[error("Missing claims in context")]
    MissingClaims,

    /// Occurs when a resource is missing from the authorization context.
    #[error("Missing resource in context")]
    MissingResource,

    /// Occurs when an unsupported or unrecognized authentication strategy is provided.
    #[error("Invalid strategy in context: {0}")]
    InvalidStrategy(String),
}

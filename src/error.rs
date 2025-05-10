use thiserror::Error;

/// Represents all possible errors that can occur during authentication and authorization.
#[derive(Error, Debug, PartialEq)]
pub enum AuthError {
    /// Returned when a user record cannot be found in the data source.
    #[error("User not found")]
    UserNotFound,

    /// Returned when the provided password does not match the stored hash.
    #[error("Invalid password")]
    InvalidPassword,

    /// Returned when attempting to register an email that already exists.
    #[error("Email is already registered")]
    EmailAlreadyRegistered,

    /// Returned when a token is missing, malformed, or expired.
    #[error("Invalid or expired token")]
    InvalidToken,

    /// Returned when the user does not have the required permission for a service.
    #[error("Access denied to user '{user}' for service '{service}' with permission '{permission}'")]
    AccessDenied {
        /// Identifier of the user being denied.
        user: String,
        /// Name of the service being accessed.
        service: String,
        /// The required permission that was not granted.
        permission: String,
    },

    /// Returned when password hashing fails due to an internal error.
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),

    /// Returned when no user is present in the authorization context.
    #[error("Missing user in context")]
    MissingUser,

    /// Returned when no claims are present in the authorization context.
    #[error("Missing claims in context")]
    MissingClaims,

    /// Returned when no resource is present in the authorization context.
    #[error("Missing resource in context")]
    MissingResource,
}

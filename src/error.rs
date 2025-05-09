use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Email is already registered")]
    EmailAlreadyRegistered,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Access denied to user '{user}' for service '{service}' with permission '{permission}'")]
    AccessDenied {
        user: String,
        service: String,
        permission: String,
    },

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),

    #[error("Missing user in context")]
    MissingUser,

    #[error("Missing claims in context")]
    MissingClaims,

    #[error("Missing resource in context")]
    MissingResource,
}

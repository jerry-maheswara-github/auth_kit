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

    #[error("Access denied to service '{service}' with permission '{permission}'")]
    AccessDenied {
        service: String,
        permission: String,
    },

    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),
}

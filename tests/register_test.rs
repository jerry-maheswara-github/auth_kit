#[cfg(test)]
mod tests {
    use auth_kit::auth::auth_n::Authentication;
    use auth_kit::error::AuthError;

    #[test]
    fn test_reset_password_success() {
        let mut auth = Authentication::new();
        let email = "user@example.com";
        let old_hash = "old_hash";
        let new_hash = "new_hash";
        let token = "valid_token";

        auth.register(email, old_hash).unwrap();

        let result = auth.reset_password(email, token, new_hash, |t| t == "valid_token");
        assert!(result.is_ok());

        let user = auth.login(email).unwrap().unwrap();
        assert_eq!(user.password_hash, new_hash);
    }

    #[test]
    fn test_reset_password_invalid_token() {
        let mut auth = Authentication::new();
        let email = "user@example.com";
        let old_hash = "old_hash";
        let new_hash = "new_hash";
        let token = "invalid_token";

        auth.register(email, old_hash).unwrap();

        let result = auth.reset_password(email, token, new_hash, |t| t == "valid_token");
        assert_eq!(result, Err(AuthError::InvalidToken));

        let user = auth.login(email).unwrap().unwrap();
        assert_eq!(user.password_hash, old_hash);
    }

    #[test]
    fn test_reset_password_user_not_found() {
        let mut auth = Authentication::new();
        let result = auth.reset_password("missing@example.com", "token", "new_hash", |_| true);
        assert_eq!(result, Err(AuthError::UserNotFound));
    }
}

#[cfg(test)]
mod tests {
    use auth_kit::auth::scope::{authorize_with_matcher, FlexibleMatcher};

    #[test]
    fn test_exact_match() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("read:users", "read:users"));
    }

    #[test]
    fn test_wildcard_permission() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("read:*", "read:users"));
        assert!(!authorize_with_matcher::<FlexibleMatcher>("read:*", "write:users"));
    }

    #[test]
    fn test_wildcard_service() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("*:users", "read:users"));
        assert!(!authorize_with_matcher::<FlexibleMatcher>("*:admin", "read:users"));
    }

    #[test]
    fn test_multiple_scopes_space_separated() {
        let user_scopes = "read:posts write:users";
        assert!(authorize_with_matcher::<FlexibleMatcher>(user_scopes, "write:users"));
        assert!(!authorize_with_matcher::<FlexibleMatcher>(user_scopes, "admin:users"));
    }

    #[test]
    fn test_different_delimiters() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("read.users", "read.users"));
        assert!(authorize_with_matcher::<FlexibleMatcher>("read@users", "read@users"));
        assert!(authorize_with_matcher::<FlexibleMatcher>("read/users", "read/users"));
    }

    #[test]
    fn test_fallback_to_wildcard() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("*", "read:users"));
    }

    #[test]
    fn test_three_part_scope() {
        assert!(authorize_with_matcher::<FlexibleMatcher>("user_service:user:read", "user_service:user:read"));
        assert!(authorize_with_matcher::<FlexibleMatcher>("user_service:*:read", "user_service:user:read"));
        assert!(authorize_with_matcher::<FlexibleMatcher>("*:*:read", "user_service:user:read"));
        assert!(!authorize_with_matcher::<FlexibleMatcher>("user_service:user:write", "user_service:user:read"));
    }
}

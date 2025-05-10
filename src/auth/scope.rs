/// The `ScopeMatcher` trait defines how to match a user's scope token
/// against a required scope token. This abstraction allows for flexible
/// matching logic, including support for different delimiters and wildcards.
pub trait ScopeMatcher {
    /// Returns `true` if the `user_token` is considered to match the `required_token`.
    fn matches(user_token: &str, required_token: &str) -> bool;
}

/// A flexible implementation of `ScopeMatcher` that supports common delimiters
/// like `:`, `.`, `@`, `/`, and wildcard `*` matching.
///
/// Examples of supported formats:
/// - `read:users`
/// - `read.users`
/// - `write@admin`
/// - `resource/action`
/// - `*:*` (wildcard match)
pub struct FlexibleMatcher;

impl ScopeMatcher for FlexibleMatcher {
    fn matches(user_token: &str, required_token: &str) -> bool {
        let delimiters = [":", ".", "@", "/"];
        for delim in delimiters {
            if user_token.contains(delim) || required_token.contains(delim) {
                let (us, up) = split(user_token, delim);
                let (rs, rp) = split(required_token, delim);
                return (us == "*" || us == rs) && (up == "*" || up == rp);
            }
        }

        // Fallback to exact match or full wildcard
        user_token == required_token || user_token == "*"
    }
}

/// Splits a scope token string into two parts using the first occurrence
/// of the provided delimiter. If the delimiter is not found, defaults to "*".
///
/// # Example
/// ```code
/// let (a, b) = split("read:users", ":");
/// assert_eq!((a, b), ("read", "users"));
/// ```
fn split<'a>(scope: &'a str, delim: &'a str) -> (&'a str, &'a str) {
    let mut parts = scope.splitn(2, delim);
    let a = parts.next().unwrap_or("*");
    let b = parts.next().unwrap_or("*");
    (a, b)
}

/// Parses a scope string into a list of individual scope tokens,
/// separated by whitespace (as per OAuth2/RFC conventions).
///
/// # Example
/// ```code
/// let scopes = parse_scope_string("read:users write:posts");
/// assert_eq!(scopes, vec!["read:users", "write:posts"]);
/// ```
pub fn parse_scope_string(scope_str: &str) -> Vec<&str> {
    scope_str.split_whitespace().collect()
}

/// Checks if a required scope is authorized by any of the user's scopes
/// using the given `ScopeMatcher` implementation.
///
/// # Arguments
/// - `user_scope_str`: space-delimited string of scopes from the user (e.g. from claims or roles)
/// - `required_token`: the scope token required for the action (e.g. `"read:users"`)
///
/// # Returns
/// - `true` if at least one user scope matches the required scope using the matcher.
///
/// # Example
/// ```bash
/// let authorized = authorize_with_matcher::<FlexibleMatcher>("read:users write:posts", "read:users");
/// assert!(authorized);
/// ```
pub fn authorize_with_matcher<M: ScopeMatcher>(
    user_scope_str: &str,
    required_token: &str,
) -> bool {
    let tokens = parse_scope_string(user_scope_str);
    tokens.iter().any(|token| M::matches(token, required_token))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

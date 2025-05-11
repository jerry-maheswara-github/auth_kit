/// The `ScopeMatcher` trait defines how to match a user's scope token
/// against a required scope token. This abstraction allows for flexible
/// matching logic, including support for different delimiters and wildcards.
pub trait ScopeMatcher {
    /// Returns `true` if the `user_token` is considered to match the `required_token`.
    fn matches(user_token: &str, required_token: &str) -> bool;
}

/// A flexible implementation of the `ScopeMatcher` trait that supports
/// multipart scope token matching with common delimiters and wildcards.
///
/// This matcher is designed to handle both two-part and three-part
/// scope formats, such as:
/// - `read:users`
/// - `user_service:user:read`
///
/// It supports the following features:
/// - Matching with delimiters: `:`, `.`, `@`, and `/`
/// - Partial or full wildcard matching using `*`
/// - Graceful fallback to exact match or global wildcard
///
/// # Matching Examples
/// - `"user_service:user:read"` matches `"user_service:user:read"`
/// - `"user_service:*:read"` matches `"user_service:user:read"`
/// - `"*:*:read"` matches `"user_service:user:read"`
/// - `"read:users"` matches `"read:users"`
///
/// This makes it suitable for hybrid authorization systems that mix
/// service-level and resource-level scopes.
///
/// ## Note:
/// Both user and required tokens must use the same delimiter to match.
pub struct FlexibleMatcher;

impl ScopeMatcher for FlexibleMatcher {
    fn matches(user_token: &str, required_token: &str) -> bool {
        let delimiters = [":", ".", "@", "/"];

        for delim in delimiters {
            let u_parts: Vec<&str> = user_token.split(delim).collect();
            let r_parts: Vec<&str> = required_token.split(delim).collect();

            if u_parts.len() == r_parts.len() && u_parts.len() >= 2 {
                let mut matched = true;
                for (u, r) in u_parts.iter().zip(r_parts.iter()) {
                    if *u != "*" && *u != *r {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    return true;
                }
            }
        }

        user_token == required_token || user_token == "*"
    }
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

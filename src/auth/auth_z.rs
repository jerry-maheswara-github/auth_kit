/// Provides authorization logic using various strategies such as ABAC, RBAC, and SBA (Scope-Based Access).
///
/// The `Authorization` struct supports different models of access control and delegates the actual
/// decision-making to the strategy selected at initialization.
use crate::auth::scope::{authorize_with_matcher, FlexibleMatcher};
use crate::error::AuthError;
use crate::model::{AuthContext, AuthStrategy, Identifiable, Resource};

/// Core struct representing the authorization engine.
///
/// This struct holds the selected `AuthStrategy` (e.g., ABAC, RBAC, SBA) and
/// performs access checks based on the provided context and parameters.
pub struct Authorization {
    strategy: AuthStrategy,
}

impl Authorization {
    /// Creates a new `Authorization` instance with the given strategy name.
    ///
    /// # Arguments
    /// * `strategy` - A string representing the strategy name (e.g., `"ABAC"`, `"RBAC"`, `"SBA"`).
    ///
    /// # Returns
    /// * `Ok(Self)` if the strategy name is valid.
    /// * `Err` if the strategy name is unknown or unsupported.
    ///
    /// # Example
    /// ```code
    /// let auth = Authorization::new("RBAC")?;
    /// ```
    pub fn new(strategy: &str) -> Result<Self, AuthError> {
        let strategy = AuthStrategy::from_str(strategy)?;
        Ok(Self { strategy })
    }

    /// Authorizes access to a given service and permission using the selected strategy.
    ///
    /// # Arguments
    /// * `context` - An `AuthContext` that holds the user, claims, and optional resource.
    /// * `service` - The target service being accessed.
    /// * `permission` - The required permission or action (e.g., `"read"`, `"create"`).
    /// * `delimiter` - Optional delimiter used in scope tokens (default is `"."` if None).
    ///
    /// # Returns
    /// * `Ok(())` if the access is granted.
    /// * `Err(AuthError)` if access is denied or required context is missing.
    ///
    /// # Behavior
    /// - **ABAC**: Compares user's department and clearance with resource requirements.
    /// - **RBAC**: Checks if the user's role contains the requested permission.
    /// - **SBA**: Matches candidate scope strings using the user's claims and a flexible matcher.
    pub fn authorize(
        &mut self,
        context: &AuthContext,
        service: &str,
        permission: &str,
        delimiter: Option<&str>,
    ) -> Result<(), AuthError> {
        match self.strategy {
            AuthStrategy::ABAC => {
                let user = context.user.clone().ok_or(AuthError::MissingUser)?;
                let resource = context.resource.clone().ok_or(AuthError::MissingResource)?;
                gen_authorize(&user, service, permission, |u, _, _| {
                    u.department == resource.department && u.clearance_level >= resource.required_level
                })
            }

            AuthStrategy::RBAC => {
                let user = context.user.clone().ok_or(AuthError::MissingUser)?;
                gen_authorize(&user, service, permission, |u, _, p| {
                    u.role.permissions.iter().any(|perm| format!("{:?}", perm).eq_ignore_ascii_case(p))
                })
            }

            AuthStrategy::SBA => {
                let claims = context.claims.clone().ok_or(AuthError::MissingClaims)?;
                let resource = context.resource.clone().unwrap_or_else(|| Resource {
                    department: "*".to_string(),
                    required_level: 0,
                });
                let delim = delimiter.unwrap_or(".");
                let candidates = vec![
                    format!("{}{}{}{}{}", service, delim, resource.department, delim, permission),
                    format!("{}{}{}", service, delim, permission),
                    format!("{}", permission),
                ];
                let scopes = claims.scopes.join(" ");

                gen_authorize(&claims, service, permission, |_, _, _| {
                    candidates.iter().any(|candidate| {
                        authorize_with_matcher::<FlexibleMatcher>(&scopes, candidate)
                    })
                })
            }
        }
    }
}

/// A generic authorization function that evaluates access by executing a permission check closure.
///
/// # Arguments
/// * `user` - A reference to an object implementing the `Identifiable` trait.
/// * `service` - The service being accessed.
/// * `permission` - The permission being requested.
/// * `check_permission` - A closure that performs the actual authorization logic.
///
/// # Returns
/// * `Ok(())` if access is granted.
/// * `Err(AuthError::AccessDenied)` if the permission check fails.
///
/// # Example
/// ```code
/// gen_authorize(&user, "admin_service", "read", |u, _, _| {
///     u.role.permissions.contains(&"admin_service.read".to_string())
/// })?;
/// ```
pub fn gen_authorize<U, S, P, F>(
    user: &U,
    service: S,
    permission: P,
    check_permission: F,
) -> Result<(), AuthError>
where
    F: Fn(&U, &S, &P) -> bool,
    U: Identifiable,
    S: ToString,
    P: ToString,
{
    if check_permission(user, &service, &permission) {
        Ok(())
    } else {
        Err(AuthError::AccessDenied {
            user: user.identity(),
            service: service.to_string(),
            permission: permission.to_string(),
        })
    }
}

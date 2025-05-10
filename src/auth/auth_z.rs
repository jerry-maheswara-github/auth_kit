use crate::auth::scope::{authorize_with_matcher, FlexibleMatcher};
use crate::error::AuthError;
use crate::model::{AuthContext, AuthStrategy, Identifiable};

pub struct Authorization {
    strategy: AuthStrategy, 
}


impl Authorization {
    pub fn new(strategy: &str) -> Result<Self, &'static str> {
        let strategy = AuthStrategy::from_str(strategy)?;
        Ok(Self { strategy })
    }
    
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
                gen_authorize(&user, service, permission, |u , _, _| {
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
                let required = format!("{}{:?}{}", service, delimiter, permission);

                let scope_str = claims.scopes.join(" ");

                gen_authorize(&claims, service, permission, |_, _, _| {
                    authorize_with_matcher::<FlexibleMatcher>(&scope_str, &required)
                })
            }
        }
    }

}


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

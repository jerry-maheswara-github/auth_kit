use crate::error::AuthError;
use crate::model::{AuthContext, AuthStrategy, Identifiable};

pub struct Authorizator {
    strategy: AuthStrategy, 
}


impl Authorizator {
    pub fn new(strategy: &str) -> Result<Self, &'static str> {
        let strategy = AuthStrategy::from_str(strategy)?;
        Ok(Self { strategy })
    }
    
    pub fn authorize_with_strategy(
        &mut self,
        context: &AuthContext,
        service: &str,
        permission: &str,
    ) -> Result<(), AuthError> {
        match self.strategy {
            AuthStrategy::RBAC => {
                let user = context.user.ok_or(AuthError::MissingUser)?;
                authorize(user, service, permission, |u, _, p| {
                    u.role.permissions.iter().any(|perm| format!("{:?}", perm).eq_ignore_ascii_case(p))
                })
            }

            AuthStrategy::JWT => {
                let claims = context.claims.ok_or(AuthError::MissingClaims)?;
                authorize(claims, service, permission, |c, s, p| {
                    let scope = format!("{}:{}", s, p);
                    c.scopes.contains(&scope)
                })
            }

            AuthStrategy::ABAC => {
                let user = context.user.ok_or(AuthError::MissingUser)?;
                let resource = context.resource.ok_or(AuthError::MissingResource)?;
                authorize(user, service, permission, |u, _, _| {
                    u.department == resource.department && u.clearance_level >= resource.required_level
                })
            }
        }
    }

}


pub fn authorize<U, S, P, F>(
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

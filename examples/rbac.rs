use auth_kit::auth::auth_n::Authentication;
use auth_kit::auth::auth_z::Authorization;
use auth_kit::error::AuthError;
use auth_kit::model::{AuthContext, Permission};
use bcrypt::{hash, DEFAULT_COST};

fn main() -> Result<(), AuthError> {
    let mut authenticator = Authentication::new();
    let authorized = Authorization::new("RBAC");

    let password_hash = hash("secret123", DEFAULT_COST)
        .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;

    match authenticator.register("admin@example.com", &password_hash) {
        Ok(()) => println!("User registered"),
        Err(AuthError::EmailAlreadyRegistered) => println!("Email already in use"),
        Err(e) => eprintln!("Registration failed: {:?}", e),
    }

    let mut user = authenticator.users.get("admin@example.com").cloned().expect("User must exist");
    user.role.permissions.push(Permission::Create);

    match authorized {
        Ok(mut auth) => {
            let context = AuthContext {
                user: Some(user),
                claims: None,
                resource: None,
            };
            let result = auth.authorize(&context, "service", "create", None);
            match result {
                Ok(_) => println!("Access granted via RBAC."),
                Err(e) => println!("Access denied: {}", e.to_string()),
            }
        },
        Err(e) => {
            println!("Error initializing Authorization: {}", e.to_string());
        }
    }

    Ok(())
}
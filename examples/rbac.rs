use auth_kit::auth::authenticator::Authenticator;
use auth_kit::auth::authorizator::Authorizator;
use auth_kit::error::AuthError;
use auth_kit::model::{AuthContext, Permission};
use bcrypt::{hash, DEFAULT_COST};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut authenticator = Authenticator::new();
    let authorized = Authorizator::new("RBAC");
    

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
                user: Some(&user),
                claims: None,
                resource: None,
            };
            let result = auth.authorize_with_strategy(&context, "service", "create");
            match result {
                Ok(_) => println!("✅  Access granted via RBAC."),
                Err(e) => println!("❌  Access denied: {:?}", e),
            }
        },
        Err(e) => {
            println!("Error initializing Authorizator: {}", e);
        }
    }

    Ok(())
}
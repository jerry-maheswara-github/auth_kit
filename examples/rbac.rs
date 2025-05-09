use auth_kit::auth::*;
use bcrypt::{hash, DEFAULT_COST};
use auth_kit::error::AuthError;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut auth = Authenticator::new();

    let password_hash = hash("secret123", DEFAULT_COST)
        .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;
    
    match auth.register("admin@example.com", &password_hash) {
        Ok(()) => println!("User registered"),
        Err(AuthError::EmailAlreadyRegistered) => println!("Email already in use"),
        Err(e) => eprintln!("Registration failed: {:?}", e),
    }
    
    let mut user = auth.users.get("admin@example.com").cloned().expect("User must exist");
    user.role.permissions.push(Permission::Create);
    
    let context = AuthContext {
        user: Some(&user),
        claims: None,
        resource: None,
    };

    let result = auth.authorize_with_strategy(&context, AuthStrategy::RBAC, "admin_service", "create");
    match result {
        Ok(_) => println!("✅ Access granted via RBAC."),
        Err(e) => println!("❌  {}", e),
    }
    Ok(())
}
use bcrypt::{hash, verify, DEFAULT_COST};
use auth_kit::auth::authenticator::Authenticator;
use auth_kit::error::AuthError;
use auth_kit::model::Permission;

fn main() -> Result<(), AuthError> {
    let mut auth = Authenticator::new();

    // Hash the password before registration
    let password_hash = hash("secret123", DEFAULT_COST)
        .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;

    // Register the user
    match auth.register("admin@example.com", &password_hash) {
        Ok(()) => println!("✅ User registered successfully."),
        Err(AuthError::EmailAlreadyRegistered) => println!("⚠️ Email is already in use."),
        Err(e) => {
            eprintln!("❌ Failed to register user: {:?}", e);
            return Err(e);
        }
    }

    // Add permission to the newly registered user
    if let Some(user) = auth.users.get_mut("admin@example.com") {
        user.role.permissions.push(Permission::Create);
    }

    // Attempt login and password verification
    match auth.login("admin@example.com") {
        Ok(Some(user)) => {
            match verify("secret123", &user.password_hash) {
                Ok(true) => {
                    println!("✅ Login successful for user: {}", user.email);
                    // Proceed with authorization or next steps
                }
                Ok(false) => {
                    println!("❌ Incorrect password.");
                }
                Err(e) => {
                    eprintln!("❌ Password verification failed: {:?}", e);
                    return Err(AuthError::PasswordHashingFailed(e.to_string()));
                }
            }
        }
        Ok(None) => {
            println!("❌ User not found.");
        }
        Err(e) => {
            eprintln!("❌ Error while retrieving user: {:?}", e);
            return Err(e);
        }
    }

    Ok(())
}

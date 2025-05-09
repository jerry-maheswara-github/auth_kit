use bcrypt::{hash, DEFAULT_COST};
use auth_kit::auth::{AuthContext, AuthStrategy, Authenticator, Claims, Permission, Resource, Role};
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

    {
        let user = auth.users.get_mut("admin@example.com").unwrap();
        user.role = Role {
            name: "admin".to_string(),
            permissions: vec![Permission::Create, Permission::Read],
        };
        user.department = "engineering".to_string();
        user.clearance_level = 5;
    }

    let user = auth
        .login("admin@example.com")
        .expect("Login failed")
        .unwrap();

    // =================== RBAC ========================================
    let rbac_context = AuthContext {
        user: Some(&user),
        claims: None,
        resource: None,
    };

    let result = auth.authorize_with_strategy(
        &rbac_context,
        AuthStrategy::RBAC,
        "admin_service",
        "create",
    );

    match result {
        Ok(_) => println!("✅ Access granted via RBAC."),
        Err(e) => println!("❌ Access denied: {}", e),
    }

    // =================== ABAC ========================================
    let resource = Resource {
        department: "engineering".to_string(),
        required_level: 3,
    };

    let abac_context = AuthContext {
        user: Some(&user),
        claims: None,
        resource: Some(&resource),
    };

    let abac_result = auth.authorize_with_strategy(
        &abac_context,
        AuthStrategy::ABAC,
        "internal_docs",
        "read",
    );

    match abac_result {
        Ok(_) => println!("✅ Access granted via ABAC."),
        Err(e) => println!("❌ ABAC check failed: {}", e),
    }

    // =================== JWT ========================================
    let claims = Claims {
        email: "jwtuser@example.com".to_string(),
        service: "admin_service".to_string(),
        scopes: vec![
            "admin_service:create".to_string(),
            "admin_service:read".to_string(),
        ],
    };

    let context = AuthContext {
        user: None,
        claims: Some(&claims),
        resource: None,
    };

    let result = auth.authorize_with_strategy(
        &context,
        AuthStrategy::JWT,
        "admin_service",
        "create",
    );

    match result {
        Ok(_) => println!("✅ Access granted via JWT."),
        Err(e) => println!("❌ Access denied via JWT: {}", e),
    }

    let denied = auth.authorize_with_strategy(
        &context,
        AuthStrategy::JWT,
        "admin_service",
        "delete",
    );

    match denied {
        Ok(_) => println!("✅ Unexpected access granted!"),
        Err(e) => println!("❌ As expected, access denied: {}", e),
    }
    
    Ok(())
}

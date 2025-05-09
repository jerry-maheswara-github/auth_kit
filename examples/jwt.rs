use auth_kit::auth::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        email: "jwt@example.com".to_string(),
        service: "admin_service".to_string(),
        scopes: vec!["admin_service:create".to_string()],
    };

    let context = AuthContext {
        user: None,
        claims: Some(&claims),
        resource: None,
    };

    let mut auth = Authenticator::new();
    let result = auth.authorize_with_strategy(&context, AuthStrategy::JWT, "admin_service", "create");
    match result {
        Ok(_) => println!("✅ Access granted via JWT."),
        Err(e) => println!("❌ Access denied via JWT: {}", e),
    }

    Ok(())
}
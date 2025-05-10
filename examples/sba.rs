use auth_kit::auth::auth_z::Authorization;
use auth_kit::model::{AuthContext, Claims};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let claims = Claims {
        email: "jwt@example.com".to_string(),
        service: "admin_service".to_string(),
        scopes: vec!["admin_service.read".to_string(), "admin_service.create".to_string()],
    };

    let context = AuthContext {
        user: None,
        claims: Some(claims),
        resource: None,
    };

    let authorized = Authorization::new("SBA");
    match authorized {
        Ok(mut auth) => {
            let result = auth.authorize(&context, "admin_service", "read", Some(":"));
            match result {
                Ok(_) => println!("✅ Access granted via SBA."),
                Err(e) => println!("❌ Access denied via SBA: {}", e),
            }
        },
        Err(e) => {
            println!("Error initializing Authorization: {}", e);
        }
    }

    Ok(())
}
use auth_kit::auth::auth_z::Authorization;
use auth_kit::error::AuthError;
use auth_kit::model::{AuthContext, Claims, Resource};

fn main() -> Result<(), AuthError> {
    let claims = Claims {
        email: "jwt@example.com".to_string(),
        service: "admin_service".to_string(),
        scopes: vec!["admin_service.read".to_string(), "admin_service.create".to_string()],
    };
    
    let resource = Resource {
        department: "engineering".to_string(),
        required_level: 3,
    };
    
    let context = AuthContext {
        user: None,
        claims: Some(claims),
        resource: Some(resource),
    };

    let authorized = Authorization::new("SBA");
    match authorized {
        Ok(mut auth) => {
            let result = auth.authorize(&context, "admin_service", "read", None);
            match result {
                Ok(_) => println!("Access granted via SBA."),
                Err(e) => println!("Access denied via SBA: {}", e.to_string()),
            }
        },
        Err(e) => {
            println!("Error initializing Authorization: {}", e.to_string());
        }
    }

    Ok(())
}
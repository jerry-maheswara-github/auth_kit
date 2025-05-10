use auth_kit::auth::auth_z::Authorization;
use auth_kit::model::{AuthContext, Resource, Role, User};

fn main() -> Result<(), Box<dyn std::error::Error>> {
     let user = User {
         email: "abac@example.com".to_string(),
         password_hash: "".to_string(),
         role: Role {
             name: "employee".to_string(),
             permissions: vec![],
         },
         department: "engineering".to_string(),
         clearance_level: 5,
     };

     let resource = Resource {
         department: "engineering".to_string(),
         required_level: 3,
     };

     let context = AuthContext {
         user: Some(user),
         claims: None,
         resource: Some(resource),
     };

     let authorized = Authorization::new("ABAC");
     match authorized {
        Ok(mut auth) => {
            let result = auth.authorize(&context, "", "", None);
            match result {
                Ok(_) => println!("✅ Access granted via ABAC."),
                Err(e) => println!("❌ ABAC check failed: {}", e),
            }

        },
        Err(e) => {
            println!("Error initializing Authorization: {}", e);
        }
     }

     Ok(())
 }
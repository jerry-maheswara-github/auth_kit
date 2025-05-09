use auth_kit::auth::*;

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
         user: Some(&user),
         claims: None,
         resource: Some(&resource),
     };

     let mut auth = Authenticator::new();
     let result = auth.authorize_with_strategy(&context, AuthStrategy::ABAC, "docs", "read");
     match result {
         Ok(_) => println!("✅ Access granted via ABAC."),
         Err(e) => println!("❌ ABAC check failed: {}", e),
     }
     Ok(())
 }
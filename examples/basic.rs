use auth_kit::auth::{Authenticator, User};

fn main() {
    let mut auth = Authenticator::new();

    match auth.register("admin@example.com", "admin_password") {
        Ok(_) => println!("User registered successfully."),
        Err(e) => println!("Error registering user: {}", e),
    }

    match auth.login("admin@example.com", "admin_password") {
        Ok(Some(user)) => {
            println!("Login successful for user: {}", user.email);
        }
        Err(e) => println!("Login failed: {}", e),
        _ => {}
    }

    let token = "some_token";  
    let new_password = "new_password123";
    match auth.reset_password("admin@example.com", token, new_password, |token| token == "some_token") {
        Ok(_) => println!("Password reset successful."),
        Err(e) => println!("Password reset failed: {}", e),
    }

    let user = User {
        email: "user@example.com".to_string(),
        password_hash: "user_password".to_string(),
    };

    match auth.authorize(&user, "admin_service", "create", |_user, service, permission| {
        service == "admin_service" && permission == "create"  
    }) {
        Ok(_) => println!("Access granted to service."),
        Err(e) => println!("Access denied: {}", e),
    }
    eprintln!("{:?}", user);
}

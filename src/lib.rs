//! # Toolkit for Authentication and Authorization in Rust
//!
//! A flexible and extensible authentication and authorization library in Rust,
//! designed to support multiple strategies including **ABAC** (Attribute-Based Access Control),
//! **RBAC** (Role-Based Access Control), and **SBA** (Scope-Based Authorization)
//!
//! This crate is suitable for use in both API servers and embedded authorization layers.
//! 
//! ---
//! 
//! ## ✨ Features
//! 
//! - **Authentication (auth_n)**: Handles register, login, and reset_password.
//! - **Authorization (auth_z)**: Supports **ABAC** (Attribute-Based Access Control), 
//!   **RBAC** (Role-Based Access Control), and **SBA** (Scope-Based Authorization)
//! - **Scope matching**: Flexible support for OAuth2-style scopes with customizable formats.
//!
//!---
//! 
//! ## 🚀 Quick Start
//!
//!
//! ### 🏢 ABAC (Attribute-Based Access Control)
//!
//!```rust
//! use auth_kit::auth::auth_z::Authorization;
//! use auth_kit::model::{AuthContext, AuthStrategy, Resource, Role, User};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let user = User {
//!         email: "abac@example.com".to_string(),
//!         password_hash: "".to_string(),
//!         role: Role {
//!             name: "employee".to_string(),
//!             permissions: vec![],
//!         },
//!         department: "engineering".to_string(),
//!         clearance_level: 5,
//!     };
//!
//!     let resource = Resource {
//!         department: "engineering".to_string(),
//!         required_level: 3,
//!     };
//!
//!     let context = AuthContext {
//!         user: Some(user),
//!         claims: None,
//!         resource: Some(resource),
//!     };
//!
//!      let authorized = Authorization::new("ABAC");
//!      match authorized {
//!         Ok(mut authz) => {
//!             let result = authz.authorize(&context, "docs", "read", None);
//!             match result {
//!                 Ok(_) => println!("Access granted via ABAC."),
//!                 Err(e) => println!("ABAC check failed: {}", e),
//!             }
//!             
//!         },
//!         Err(e) => {
//!             println!("Error initializing Authorization: {}", e);
//!         }
//!      }
//!
//!     Ok(())
//! }
//! ```
//! 
//!
//! ### 🔐 RBAC (Role-Based Access Control)
//!
//!```rust
//! use bcrypt::{hash, DEFAULT_COST};
//! use auth_kit::error::AuthError;
//! use auth_kit::auth::auth_n::Authentication;
//! use auth_kit::auth::auth_z::Authorization;
//! use auth_kit::model::{AuthContext, AuthStrategy, Permission};
//!
//! fn main() -> Result<(), AuthError> {
//!
//!     let mut authn = Authentication::new();
//!
//!     let password_hash = hash("secret123", DEFAULT_COST)
//!         .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;
//!
//!     match authn.register("admin@example.com", &password_hash) {
//!         Ok(()) => println!("User registered"),
//!         Err(AuthError::EmailAlreadyRegistered) => println!("Email already in use"),
//!         Err(e) => eprintln!("Registration failed: {:?}", e),
//!     }
//!
//!     let mut user = authn.users.get("admin@example.com").cloned().expect("User must exist");
//!     user.role.permissions.push(Permission::Create);
//!
//!     let authorized = Authorization::new("RBAC");
//!     match authorized {
//!         Ok(mut authz) => {
//!             let context = AuthContext {
//!                 user: Some(user),
//!                 claims: None,
//!                 resource: None,
//!             };
//!             let result = authz.authorize(&context, "service", "create", None);
//!             match result {
//!                 Ok(_) => println!("Access granted via RBAC."),
//!                 Err(e) => println!("Access denied: {:?}", e),
//!             }
//!         },
//!         Err(e) => {
//!             println!("Error initializing Authorization: {}", e);
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 🪪 SBA (Scope-Based Authorization)
//!
//! ```rust
//! use auth_kit::auth::auth_z::Authorization;
//! use auth_kit::model::{AuthContext, AuthStrategy, Claims};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let claims = Claims {
//!         email: "jwt@example.com".to_string(),
//!         service: "admin_service".to_string(),
//!         scopes: vec!["admin_service:create".to_string()],
//!     };
//!
//!     let context = AuthContext {
//!         user: None,
//!         claims: Some(claims),
//!         resource: None,
//!     };
//!
//!     let authorized = Authorization::new("SBA");
//!     match authorized {
//!         Ok(mut authz) => {
//!             let result = authz.authorize(&context, "admin_service", "create", Some(":"));
//!             match result {
//!                 Ok(_) => println!("Access granted via SBA."),
//!                 Err(e) => println!("Access denied via SBA: {}", e),
//!             }
//!         },
//!         Err(e) => {
//!             println!("Error initializing Authorization: {}", e);
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ---
//! 
//! ## 📜  License
//! 
//! Licensed under:
//! - Apache License, Version 2.0 [LICENSE](http://www.apache.org/licenses/LICENSE-2.0.txt)
//! 
//! ---
//!
//! ## 🧑‍💻 Author
//!
//! Created and maintained by [Jerry Maheswara](https://github.com/jerry-maheswara-github)
//!
//! Feel free to reach out for suggestions, issues, or improvements!
//!
//! ---
//!
//! ## ❤️ Built with Love in Rust
//!
//! This project is built with ❤️ using **Rust** — a systems programming language that is safe, fast, and concurrent. Rust is the perfect choice for building reliable and efficient applications.
//!
//! ---
//!
//! ## 👋 Contributing
//!
//! Pull requests, issues, and feedback are welcome!  
//! If you find this crate useful, give it a ⭐ and share it with others in the Rust community.
//!
//! ---

/// Error definitions and shared error types.
pub mod error;

/// Authentication and authorization logic.
pub mod auth;

/// Common data types used in authentication and policy evaluation.
pub mod model;
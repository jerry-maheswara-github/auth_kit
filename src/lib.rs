//! # AuthKit
//!
//! A flexible and extensible authentication and authorization library in Rust,
//! supporting multiple strategies including **ABAC** (Attribute-Based Access Control),
//! **RBAC** (Role-Based Access Control), and **SBA** (Scope-Based Authorization)
//!
//! ## ✨ Features
//!
//! - Role and permission system based on the `Permission` enum.
//! - Generic `authorize()` function with custom logic via closures.
//! - Supports multiple access strategies: ABAC, RBAC, SBA.
//! - Generic subject support via the `Identifiable` trait.
//!
//! ## 🚀 Quick Start
//!
//!
//! ### 🏢 ABAC (Attribute-Based Access Control)
//!
//! ```rust
//! use auth_kit::auth::authorizator::Authorizator;
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
//!         user: Some(&user),
//!         claims: None,
//!         resource: Some(&resource),
//!     };
//!
//!      let authorized = Authorizator::new("ABAC");
//!      match authorized {
//!         Ok(mut auth) => {
//!             let result = auth.authorize_with_strategy(&context, "docs", "read");
//!             match result {
//!                 Ok(_) => println!("✅ Access granted via ABAC."),
//!                 Err(e) => println!("❌ ABAC check failed: {}", e),
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
//! ```rust
//! use auth_kit::auth::*;
//! use bcrypt::{hash, DEFAULT_COST};
//! use auth_kit::error::AuthError;
//! use auth_kit::auth::authenticator::Authenticator;
//! use auth_kit::auth::authorizator::Authorizator;
//! use auth_kit::model::{AuthContext, AuthStrategy, Permission};
//!
//! fn main() -> Result<(), AuthError> {
//!
//!     let mut auth = Authenticator::new();
//!
//!     let password_hash = hash("secret123", DEFAULT_COST)
//!         .map_err(|e| AuthError::PasswordHashingFailed(e.to_string()))?;
//!
//!     match auth.register("admin@example.com", &password_hash) {
//!         Ok(()) => println!("User registered"),
//!         Err(AuthError::EmailAlreadyRegistered) => println!("Email already in use"),
//!         Err(e) => eprintln!("Registration failed: {:?}", e),
//!     }
//!
//!     let mut user = auth.users.get("admin@example.com").cloned().expect("User must exist");
//!     user.role.permissions.push(Permission::Create);
//!
//!     let context = AuthContext {
//!         user: Some(&user),
//!         claims: None,
//!         resource: None,
//!     };
//!
//!     let authorized = Authorizator::new("RBAC");
//!     match authorized {
//!         Ok(mut auth) => {
//!             let context = AuthContext {
//!                 user: Some(&user),
//!                 claims: None,
//!                 resource: None,
//!             };
//!             let result = auth.authorize_with_strategy(&context, "service", "create");
//!             match result {
//!                 Ok(_) => println!("✅  Access granted via RBAC."),
//!                 Err(e) => println!("❌  Access denied: {:?}", e),
//!             }
//!         },
//!         Err(e) => {
//!             println!("Error initializing Authorizator: {}", e);
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 🪪 SBA (Scope-Based Authorization)
//!
//! ```rust
//! use auth_kit::auth::*;
//!
//! use auth_kit::auth::authorizator::Authorizator;
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
//!         claims: Some(&claims),
//!         resource: None,
//!     };
//!
//!     let authorized = Authorizator::new("SBA");
//!     match authorized {
//!         Ok(mut auth) => {
//!             let result = auth.authorize_with_strategy(&context, "admin_service", "create");
//!             match result {
//!                 Ok(_) => println!("✅ Access granted via SBA."),
//!                 Err(e) => println!("❌ Access denied via SBA: {}", e),
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
//! ## License
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

pub mod error;
pub mod auth;
pub mod model;
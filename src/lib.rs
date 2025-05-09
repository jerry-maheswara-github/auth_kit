//! # AuthKit
//!
//! A flexible and extensible authentication and authorization library in Rust,
//! supporting multiple strategies including **RBAC** (Role-Based Access Control),
//! **JWT** (scope-based authorization), and **ABAC** (Attribute-Based Access Control).
//!
//! ## ✨ Features
//!
//! - Role and permission system based on the `Permission` enum.
//! - Generic `authorize()` function with custom logic via closures.
//! - Supports multiple access strategies: RBAC, JWT scopes, ABAC.
//! - Generic subject support via the `Identifiable` trait.
//!
//! ## 🚀 Quick Start
//!
//! ### 🔐 RBAC (Role-Based Access Control)
//!
//! ```rust
//! use auth_kit::auth::*;
//! use bcrypt::{hash, DEFAULT_COST};
//! use auth_kit::error::AuthError;
//! 
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//!     let result = auth.authorize_with_strategy(&context, AuthStrategy::RBAC, "admin_service", "create");
//!     match result {
//!         Ok(_) => println!("✅ Access granted via RBAC."),
//!         Err(e) => println!("❌  {}", e),
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 🪪 JWT (Scope-Based Access Control)
//!
//! ```rust
//! use auth_kit::auth::*;
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
//!     let mut auth = Authenticator::new();
//!     let result = auth.authorize_with_strategy(&context, AuthStrategy::JWT, "admin_service", "create");
//!     match result {
//!         Ok(_) => println!("✅ Access granted via JWT."),
//!         Err(e) => println!("❌ Access denied via JWT: {}", e),
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 🏢 ABAC (Attribute-Based Access Control)
//!
//! ```rust
//! use auth_kit::auth::*;
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
//!     let mut auth = Authenticator::new();
//!     let result = auth.authorize_with_strategy(&context, AuthStrategy::ABAC, "docs", "read");
//!     assert!(result.is_ok());
//!     match result {
//!          Ok(_) => println!("✅ Access granted via ABAC."),
//!          Err(e) => println!("❌ ABAC check failed: {}", e),
//!      }
//! 
//!     Ok(())
//! }
//! ```
//! ## 🔐 Generic Trait
//!
//! The `Identifiable` trait is used to support identity-based access across various types:
//!
//! ```rust
//! pub trait Identifiable {
//!     fn identity(&self) -> String;
//! }
//! ```
//!
//! This allows `authorize()` to work generically on `User`, `Claims`, or other custom types.
//!
//! ## 🧪 Run Examples
//!
//! - `cargo run --example basic` — RBAC-based access
//! - `cargo run --example jwt` — JWT scope authorization
//!
//! ## 📚 Dependencies
//!
//! - [`thiserror`](https://crates.io/crates/thiserror) — Friendly error definitions
//! - [`serde`](https://crates.io/crates/serde) — Deserialization of claims (for JWT)
//!
//! ## 📁 Example Structure
//!
//! ```text
//! auth_kit/
//! ├── src/
//! │   ├── lib.rs
//! │   └── auth.rs
//! └── examples/
//!     ├── basic.rs
//!     └── jwt.rs
//! ```
//!
//! You can extend the system with custom strategies, OAuth2 tokens, session handling, or more advanced ABAC policies.
//!
//! ---
//! 
//! ## License
//! 
//! Licensed under:
//! - Apache License, Version 2.0 [LICENSE](http://www.apache.org/licenses/LICENSE-2.0.txt)
//! 

pub mod auth;
pub mod error;
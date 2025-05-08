//! # auth_kit
//! 
//! Lightweight and Flexible Authentication and Authorization Toolkit for Rust.
//! 
//! ## Features
//! 
//! - ✅ Email-based user registration
//! - ✅ Password hashing via bcrypt
//! - ✅ Token-based password reset (external token verification)
//! - ✅ Authorization via service/permission pairing
//! - ❌ No built-in role or token logic (let the implementor handle it!)
//! 
//! ## Usage
//! 
//! ```rust
//! use auth_kit::auth::{Authenticator, User};
//! use auth_kit::error::AuthError;
//! 
//! fn main() -> Result<(), AuthError>{
//!     let mut auth = Authenticator::new();
//!     auth.register("user@example.com", "password123")?;
//! 
//!     let user = auth.login("user@example.com", "password123")?.unwrap();
//! 
//!     // Example authorization
//!     auth.authorize(&user, "blog_service", "edit_post", |user, service, permission| {
//!         user.email == "user@example.com" && permission == "edit_post"
//!     })?;
//!     Ok(())
//! }
//! ```
//! 
//! ## Design Principles
//! 
//! - **Simple and explicit**: No hidden magic, all logic exposed and controlled by implementor.
//! - **Token & role-agnostic**: Easily integrate with JWT or any custom token system.
//! - **Built for extension**: You own the policy layer. This crate stays unopinionated.
//! 
//! ## Crate Features
//! 
//! | Feature        | Description                                 |
//! |----------------|---------------------------------------------|
//! | Registration   | Create a new user with email + password     |
//! | Login          | Validate credentials and retrieve user info |
//! | Password reset | Requires external token verification         |
//! | Authorization  | Match user → service → permission           |
//! 
//! ## License
//! 
//! Licensed under either of:
//! - Apache License, Version 2.0 [LICENSE](http://www.apache.org/licenses/LICENSE-2.0.txt)
//! 
//! Your choice.
//! 

pub mod auth;
pub mod error;
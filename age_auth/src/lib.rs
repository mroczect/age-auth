//! # age-auth
//!
//! **Offline authenticator + OTP library secured by age encryption.**
//!
//! This is the root crate of the `age-auth` workspace. It re-exports all
//! public items from the sub-crates so that users only need a single
//! dependency.
//!
//! # Workspace members
//!
//! | Crate | Purpose |
//! |---|---|
//! | [`libage_auth_handler`](https://docs.rs/libage_auth_handler) | Traits, types, and error handling |
//! | [`libage_crypto`](https://docs.rs/libage_crypto) | Age encryption/decryption via `librage` |
//! | [`libage_otp`](https://docs.rs/libage_otp) | TOTP (RFC 6238) and HOTP (RFC 4226) |
//! | [`libage_authenticator`](https://docs.rs/libage_authenticator) | High-level authenticator combining crypto + OTP |
//!
//! # Quick start
//!
//! ```rust
//! use age_auth::{
//!     AgeAuthenticator, generate_keypair,
//!     traits::Authenticator,
//!     types::Secret,
//! };
//! use std::io::Cursor;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = AgeAuthenticator::new();
//! let (recipient, identity) = generate_keypair()?;
//!
//! let secret = Secret::new(b"JBSWY3DPEHPK3PXP".to_vec());
//! let encrypted = auth.provision(&recipient, &secret)?;
//!
//! let mut identity_reader = Cursor::new(identity.as_str().as_bytes());
//! let totp_code = auth.generate_totp_from_encrypted(
//!     &mut identity_reader,
//!     &encrypted,
//! )?;
//!
//! println!("Your one‑time code is: {}", totp_code);
//! # Ok(())
//! # }
//! ```
//!
//! # Security
//!
//! - Secrets are zeroized on drop.
//! - No unwrap/expect in production code.
//! - Default OTP algorithm is SHA‑256.
//! - Identity material is never stored inside the library.

pub use libage_auth_handler::*;
pub use libage_authenticator::AgeAuthenticator;
pub use libage_crypto::{AgeCrypto, encrypt_multiple, generate_keypair};
pub use libage_otp::AgeOtp;

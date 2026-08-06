//! # libage_auth_handler
//!
//! Core traits, error types, and validated wrappers for the `age-auth` workspace.
//!
//! This crate defines the contracts that every other component in the
//! workspace adheres to. It provides:
//!
//! - **Traits** – [`CryptoBackend`], [`OtpGenerator`], [`Authenticator`]
//!   that define the APIs for encryption, OTP generation, and the combined
//!   authenticator.
//! - **Validated types** – [`Recipient`], [`Identity`], [`Secret`],
//!   [`Token`], [`Base32String`], [`TimeStep`], [`Digits`], [`Counter`],
//!   [`EncryptedPayload`]. Every type ensures at construction that its
//!   value is legitimate.
//! - **Error handling** – a single [`AuthError`] enum with automatic
//!   conversions from `std::io::Error`.
//! - **Macros** – [`ensure!`] and [`bail!`] for ergonomic validation.
//!
//! # Zeroize
//! [`Secret`] and [`EncryptedPayload`] automatically zeroize their memory
//! when dropped. This reduces the risk of accidental leakage.
//!
//! # Usage
//! Add `libage_auth_handler` to your `Cargo.toml` and implement the traits
//! in your own types, or use the ready‑made implementations from
//! `libage_crypto`, `libage_otp`, and `libage_authenticator`.

pub mod constants;
pub mod enums;
pub mod errors;
pub mod macros;
pub mod traits;
pub mod types;
pub mod validation;

pub use constants::*;
pub use enums::*;
pub use errors::*;
pub use traits::*;
pub use types::*;
pub use validation::*;

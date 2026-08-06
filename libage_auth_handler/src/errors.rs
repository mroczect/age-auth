//! Unified error type for the `age-auth` workspace.
//!
//! All fallible functions in `libage_auth_handler`, `libage_crypto`,
//! `libage_otp`, and `libage_authenticator` return
//! [`Result<T>`](crate::errors::Result) which is an alias for
//! `std::result::Result<T, AuthError>`.
//!
//! `AuthError` is designed to be descriptive, easy to match, and to
//! automatically convert from `std::io::Error` and other error types.

use thiserror::Error;

/// The single error type for all `age-auth` crates.
///
/// # Variants
/// - `Crypto(String)` – cryptographic operation failed (wrong key, MAC
///   mismatch, etc.).
/// - `Otp(String)` – OTP generation failed (e.g., invalid secret or
///   unsupported algorithm).
/// - `InvalidInput(String)` – user input did not pass validation
///   (malformed recipient, identity, base32 string, …).
/// - `Io(std::io::Error)` – file or I/O error. Transparently wraps
///   `std::io::Error`.
/// - `Other(Box<dyn Error + Send + Sync>)` – catch‑all for rare or
///   unexpected errors.
///
/// # `Display` and `Error`
/// `AuthError` implements `std::error::Error` and provides human‑readable
/// messages via `Display` (powered by `thiserror`).
///
/// # Conversions
/// * `From<io::Error>` → `AuthError::Io`
/// * `From<Box<dyn Error + Send + Sync>>` → `AuthError::Other`
///
/// This allows the `?` operator to be used directly with I/O errors.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::errors::AuthError;
///
/// let err = AuthError::InvalidInput("bad recipient".into());
/// println!("{}", err); // prints "Invalid input: bad recipient"
///
/// let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
/// let auth_err: AuthError = io_err.into();
/// assert!(matches!(auth_err, AuthError::Io(_)));
/// ```

#[derive(Error, Debug)]
pub enum AuthError {
    /// Cryptography‑related failure (e.g., decryption failed, key rejected).
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// OTP generation failure (e.g., algorithm not supported, invalid secret).
    #[error("OTP error: {0}")]
    Otp(String),

    /// Input validation failure (e.g., malformed recipient, identity, or base32
    /// string).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// I/O error. Wraps `std::io::Error` transparently.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Any other error that is not covered by the specific variants.
    #[error("Unknown error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Convenience type alias for `Result<T, AuthError>`.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::errors::{AuthError, Result};
///
/// fn might_fail(ok: bool) -> Result<()> {
///     if ok {
///         Ok(())
///     } else {
///         Err(AuthError::InvalidInput("something wrong".into()))
///     }
/// }
/// ```
pub type Result<T> = std::result::Result<T, AuthError>;

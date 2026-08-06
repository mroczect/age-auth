//! Error mapping from `librage` to the workspace's `AuthError`.
//!
//! This module contains a single helper function that translates
//! [`librage::ErrorBody`] (a structured error with a machine-readable
//! `code` and a human-readable `message`) into the unified
//! [`AuthError`](libage_auth_handler::errors::AuthError) enum used
//! throughout the `age-auth` workspace.
//!
//! The mapping follows these rules:
//!
//! | `librage` error code                                     | `AuthError` variant         |
//! | -------------------------------------------------------- | --------------------------- |
//! | `INVALID_PUBLIC_KEY`, `INVALID_SSH_KEY`, `INVALID_INPUT` | `InvalidInput(String)`      |
//! | `INVALID_SECRET_KEY`                                     | `Crypto(String)`            |
//! | `IO_ERROR`                                               | `Io(std::io::Error)`        |
//! | Any other code                                           | `Crypto(String)`            |
//!
//! This ensures that key-related input errors (invalid public/SSH keys)
//! are reported as user‑facing `InvalidInput`, while a bad secret key
//! is treated as a cryptographic error (`Crypto`), because the secret
//! key is not typically entered by the end user but rather represents a
//! configuration or key‑management problem.

use libage_auth_handler::errors::AuthError;

/// Converts a [`librage::ErrorBody`] into an [`AuthError`].
///
/// The function examines the `code` field of the error body and produces
/// an appropriate `AuthError` variant. This is the single point of
/// translation between `librage`'s error model and the workspace's
/// unified error type.
///
/// # Arguments
///
/// * `body` - A reference to the error body returned by a failed
///   `librage` operation.
///
/// # Examples
///
/// ```ignore
/// # use libage_auth_handler::errors::AuthError;
/// # use libage_crypto::error::from_librage_error_body;
/// let body = librage::ErrorBody::new("INVALID_PUBLIC_KEY", "bad key");
/// let err = from_librage_error_body(&body);
/// assert!(matches!(err, AuthError::InvalidInput(_)));
///
/// let body = librage::ErrorBody::new("INVALID_SECRET_KEY", "wrong secret");
/// let err = from_librage_error_body(&body);
/// assert!(matches!(err, AuthError::Crypto(_)));
/// ```
pub(crate) fn from_librage_error_body(body: &librage::ErrorBody) -> AuthError {
    match body.code.as_str() {
        "INVALID_PUBLIC_KEY" | "INVALID_SSH_KEY" | "INVALID_INPUT" => {
            AuthError::InvalidInput(body.message.clone())
        }
        "INVALID_SECRET_KEY" => AuthError::Crypto(format!("Invalid secret key: {}", body.message)),
        "IO_ERROR" => AuthError::Io(std::io::Error::other(body.message.clone())),
        _ => AuthError::Crypto(format!("{}: {}", body.code, body.message)),
    }
}

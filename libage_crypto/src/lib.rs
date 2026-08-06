//! # libage_crypto
//!
//! Age encryption/decryption backend for the age-auth authenticator.
//!
//! This crate provides an implementation of the [`CryptoBackend`] trait using
//! the [rage](https://github.com/str4d/rage) library. It handles:
//!
//! * Encrypting plaintext secrets to age public keys (X25519 recipients)
//! * Decrypting ciphertext using age identity (secret key) strings
//! * Encrypting a single secret for multiple recipients at once
//! * Generating fresh X25519 keypairs
//!
//! All operations return `Result<_, AuthError>` and never panic in production
//! code. Ciphertext and plaintext are moved out of `Zeroizing` containers
//! with [`std::mem::take`] so that the original memory is cleared immediately.
//!
//! # Quick start
//!
//! ```rust
//! use libage_crypto::{AgeCrypto, generate_keypair};
//! use libage_auth_handler::traits::CryptoBackend;
//! use libage_auth_handler::types::Secret;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (recipient, identity) = generate_keypair()?;
//! let secret = Secret::new(b"Hello, age!".to_vec());
//!
//! let backend = AgeCrypto;
//! let encrypted = backend.encrypt(&recipient, &secret)?;
//! let decrypted = backend.decrypt(&identity, &encrypted)?;
//!
//! assert_eq!(decrypted.as_bytes(), secret.as_bytes());
//! # Ok(())
//! # }
//! ```

use libage_auth_handler::errors::{AuthError, Result};
use libage_auth_handler::traits::CryptoBackend;
use libage_auth_handler::types::{EncryptedPayload, Identity, Recipient, Secret};

mod error;

/// Zero‑sized struct that implements [`CryptoBackend`].
///
/// `AgeCrypto` delegates to the `librage` crate for the underlying
/// cryptographic operations. It handles both standard encryption and
/// decryption as well as multi‑recipient encryption via the free function
/// [`encrypt_multiple`].
///
/// # Security
///
/// * Plaintext and ciphertext are extracted from `librage`'s `Zeroizing`
///   containers with [`std::mem::take`]. The original `Zeroizing` container
///   is then dropped, zeroizing its remaining capacity.
/// * All errors are mapped to [`AuthError`]; no `unwrap` or `expect` is
///   called on untrusted data.
pub struct AgeCrypto;

impl CryptoBackend for AgeCrypto {
    /// Encrypts `plaintext` for the given `recipient` (age public key).
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - `librage` reports an error (invalid key, encryption failure, etc.)
    /// - The response from `librage` is missing the expected data or error body.
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret) -> Result<EncryptedPayload> {
        let response = librage::encrypt(plaintext.as_bytes(), recipient.as_str());

        if response.success {
            let mut output = response
                .data
                .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
            let ciphertext = std::mem::take(&mut *output.ciphertext);
            Ok(EncryptedPayload::new(ciphertext))
        } else {
            let err_body = response
                .error
                .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
            Err(error::from_librage_error_body(&err_body))
        }
    }

    /// Decrypts `ciphertext` using the provided `identity` (age secret key).
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - `librage` reports an error (wrong key, decryption failure, etc.)
    /// - The response from `librage` is missing the expected data or error body.
    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload) -> Result<Secret> {
        let response = librage::decrypt(ciphertext.as_bytes(), identity.as_str());

        if response.success {
            let mut output = response
                .data
                .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
            let plaintext = std::mem::take(&mut *output.plaintext);
            Ok(Secret::new(plaintext))
        } else {
            let err_body = response
                .error
                .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
            Err(error::from_librage_error_body(&err_body))
        }
    }
}

/// Encrypts `secret` for **multiple** recipients at once.
///
/// The resulting [`EncryptedPayload`] can be decrypted with any of the
/// corresponding identities (private keys).
///
/// # Examples
///
/// ```rust
/// # use libage_crypto::{AgeCrypto, encrypt_multiple, generate_keypair};
/// # use libage_auth_handler::traits::CryptoBackend;
/// # use libage_auth_handler::types::Secret;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (r1, id1) = generate_keypair()?;
/// let (r2, _)   = generate_keypair()?;
/// let secret = Secret::new(b"multi-recipient".to_vec());
///
/// let encrypted = encrypt_multiple(&[r1, r2], &secret)?;
/// let decrypted = AgeCrypto.decrypt(&id1, &encrypted)?;
/// assert_eq!(decrypted.as_bytes(), secret.as_bytes());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns `Err` if any of the provided recipients is invalid, encryption
/// fails, or `librage` returns an unexpected response.
pub fn encrypt_multiple(recipients: &[Recipient], secret: &Secret) -> Result<EncryptedPayload> {
    let keys: Vec<&str> = recipients.iter().map(|r| r.as_str()).collect();
    let response = librage::encrypt_multiple(secret.as_bytes(), &keys);

    if response.success {
        let mut output = response
            .data
            .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
        let ciphertext = std::mem::take(&mut *output.ciphertext);
        Ok(EncryptedPayload::new(ciphertext))
    } else {
        let err_body = response
            .error
            .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
        Err(error::from_librage_error_body(&err_body))
    }
}

/// Generates a new age X25519 keypair.
///
/// Returns a tuple `(recipient, identity)` where:
/// - `recipient` is a valid [`Recipient`] (age public key starting with `"age1"`).
/// - `identity` is a valid [`Identity`] (age secret key starting with `"AGE-SECRET-KEY-"`).
///
/// # Security
///
/// The underlying secret key is generated by `librage::generate_keypair` and
/// is automatically zeroized by `librage`. It is then moved into the
/// `Identity` string which is *not* zeroized (the caller should protect it).
///
/// # Errors
///
/// Returns `Err` if key generation fails in `librage`, or if the generated
/// key material cannot be parsed into the expected formats.
///
/// # Examples
///
/// ```rust
/// use libage_crypto::generate_keypair;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (recipient, identity) = generate_keypair()?;
/// assert!(recipient.as_str().starts_with("age1"));
/// assert!(identity.as_str().starts_with("AGE-SECRET-KEY-"));
/// # Ok(())
/// # }
/// ```
pub fn generate_keypair() -> Result<(Recipient, Identity)> {
    let kp = librage::generate_keypair();
    if !kp.success {
        let err_body = kp
            .error
            .ok_or_else(|| AuthError::Crypto("keygen failed without error body".into()))?;
        return Err(error::from_librage_error_body(&err_body));
    }

    let data = kp
        .data
        .ok_or_else(|| AuthError::Crypto("keygen succeeded without data".into()))?;
    let recipient = Recipient::new(data.public_key)
        .map_err(|e| AuthError::Crypto(format!("Invalid public key from keygen: {}", e)))?;
    let identity = Identity::new(data.secret_key.as_str())
        .map_err(|e| AuthError::Crypto(format!("Invalid secret key from keygen: {}", e)))?;

    Ok((recipient, identity))
}

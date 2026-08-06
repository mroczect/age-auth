//! Core traits for the `age-auth` workspace.
//!
//! This module defines the three main abstractions used throughout the
//! workspace:
//!
//! - [`CryptoBackend`] – encryption/decryption of secrets.
//! - [`OtpGenerator`] – TOTP/HOTP generation.
//! - [`Authenticator`] – combines the above two to provide a high‑level
//!   authenticator API.
//!
//! Implementations of these traits are provided by the other crates in the
//! workspace (`libage_crypto`, `libage_otp`, `libage_authenticator`).

use crate::enums::Algo;
use crate::errors::Result;
use crate::types::{
    Base32String, Counter, Digits, EncryptedPayload, Identity, Recipient, Secret, TimeStep, Token,
};
use std::io::Read;

/// Cryptographic backend that can encrypt and decrypt secrets using
/// [age](https://age-encryption.org) identities.
///
/// # Implementors
/// - `libage_crypto::AgeCrypto`
/// - `libage_authenticator::AgeAuthenticator`
///
/// # Safety
/// Implementations must guarantee that:
/// - The plaintext secret is never exposed after the call.
/// - The ciphertext can only be decrypted by the intended identity.
pub trait CryptoBackend {
    /// Encrypts `plaintext` for the given `recipient` (age public key).
    ///
    /// Returns the ciphertext wrapped in an [`EncryptedPayload`].
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret) -> Result<EncryptedPayload>;

    /// Decrypts `ciphertext` using the provided `identity` (age secret key).
    ///
    /// Returns the original [`Secret`].
    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload) -> Result<Secret>;
}

/// Generator for Time‑based (TOTP) and Counter‑based (HOTP) one‑time passwords.
///
/// All methods are **associated functions** (they do not take `&self`), so they
/// are called directly on the implementor type, e.g. `AgeOtp::totp(...)`.
///
/// # Implementors
/// - `libage_otp::AgeOtp`
/// - `libage_authenticator::AgeAuthenticator`
///
/// # Algorithm
/// - TOTP follows RFC 6238.
/// - HOTP follows RFC 4226.
/// - Dynamic truncation is applied according to RFC 4226 Section 5.3.
pub trait OtpGenerator {
    /// Generates a time‑based one‑time password.
    ///
    /// Uses the current system time. If the system clock is before the Unix
    /// epoch, an error is returned.
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token>;

    /// Generates a counter‑based one‑time password.
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token>;

    /// Convenience method: decodes a Base32‑encoded secret, then calls `totp`
    /// with default time step (30s), default digits (6), and the default
    /// algorithm (`Sha256`). Returns the formatted token string.
    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String>;
}

/// High‑level authenticator that combines encryption and OTP generation.
///
/// This trait is **automatically implemented** for any type that implements
/// both `CryptoBackend` and `OtpGenerator`, providing a complete offline
/// authenticator workflow.
///
/// # Provided methods
/// - `provision` – encrypt a secret.
/// - `load_encrypted_secret` – decrypt an encrypted secret.
/// - `generate_totp_from_encrypted` – decrypt and immediately generate a
///   TOTP code.
///
/// # Implementors
/// - `libage_authenticator::AgeAuthenticator`
pub trait Authenticator: CryptoBackend + OtpGenerator {
    /// Encrypts `secret` with `public_key`.
    ///
    /// This is a convenience wrapper around `CryptoBackend::encrypt`.
    fn provision(&self, public_key: &Recipient, secret: &Secret) -> Result<EncryptedPayload> {
        self.encrypt(public_key, secret)
    }

    /// Reads an identity from `identity_reader`, decrypts `encrypted`, and
    /// returns the resulting secret.
    ///
    /// The identity is read into a zeroizing buffer to prevent it from
    /// lingering in memory.
    fn load_encrypted_secret(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret>;

    /// Full pipeline: decrypts the secret, interprets it as a UTF‑8 Base32
    /// string, decodes it, and returns the current TOTP code.
    ///
    /// Default implementation uses `load_encrypted_secret` followed by
    /// `totp_now_from_base32`.
    fn generate_totp_from_encrypted(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<String> {
        let secret = self.load_encrypted_secret(identity_reader, encrypted)?;
        let secret_str = std::str::from_utf8(secret.as_bytes()).map_err(|_| {
            crate::errors::AuthError::InvalidInput("Secret is not valid UTF-8".into())
        })?;
        let base32 = Base32String::new(secret_str)?;
        Self::totp_now_from_base32(&base32)
    }
}

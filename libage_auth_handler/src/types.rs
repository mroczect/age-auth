//! Strongly typed wrappers for cryptographic and OTP parameters.
//!
//! Every public type in this module enforces validation at construction time,
//! making it impossible to represent invalid values. Sensitive types
//! ([`Secret`], [`EncryptedPayload`]) automatically zeroize their memory on
//! drop.

use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// An age‑compatible public key.
///
/// Must start with `"age1"`, be longer than 4 characters, and contain only
/// alphanumeric ASCII, `-`, or `_`.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Recipient;
///
/// let rec = Recipient::new("age1abcdefghijklmnopqrstuvwxyz")?;
/// assert_eq!(rec.as_str(), "age1abcdefghijklmnopqrstuvwxyz");
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient(String);

impl Recipient {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.starts_with("age1")
            && s.len() > 4
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            Ok(Recipient(s))
        } else {
            Err(AuthError::InvalidInput("Invalid recipient format".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An age‑compatible secret key (identity).
///
/// Must start with `"AGE-SECRET-KEY-"` and be at least 21 characters long.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Identity;
///
/// let id = Identity::new("AGE-SECRET-KEY-1abcdefghijklmnop")?;
/// assert!(id.as_str().starts_with("AGE-SECRET-KEY-"));
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity(String);

impl Identity {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.starts_with("AGE-SECRET-KEY-") && s.len() > 20 {
            Ok(Identity(s))
        } else {
            Err(AuthError::InvalidInput("Invalid identity format".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A secret byte vector.
///
/// Wraps a `Vec<u8>` and **zeroizes** the memory when dropped.
///
/// # Safety
/// - `Debug` output is intentionally empty to prevent accidental logging.
/// - `Clone` is implemented because OTP secrets may need to be reused, but
///   be aware that each clone is independently zeroized.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Secret;
///
/// let secret = Secret::new(b"shared-secret".to_vec());
/// assert_eq!(secret.len(), 13);
/// drop(secret); // memory cleared here
/// ```
#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Secret(data)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret").finish()
    }
}

impl From<Vec<u8>> for Secret {
    fn from(data: Vec<u8>) -> Self {
        Secret::new(data)
    }
}

/// An OTP token (HOTP/TOTP result).
///
/// Holds a numeric value and enforces that the value fits within the
/// requested number of digits.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Token;
///
/// let token = Token::new(123456, 6)?;
/// assert_eq!(token.format(6), "123456");
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token(u64);

impl Token {
    pub fn new(value: u64, digits: u32) -> Result<Self> {
        if digits == 0 || digits > 10 || value >= 10u64.pow(digits) {
            Err(AuthError::InvalidInput(
                "Token value does not match expected digits".into(),
            ))
        } else {
            Ok(Token(value))
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn format(&self, digits: u32) -> String {
        format!("{:0width$}", self.0, width = digits as usize)
    }
}

/// A validated Base32‑encoded string (RFC 4648, no padding).
///
/// # Validation
/// The string is validated at construction time by attempting to decode it.
/// Only uppercase letters A‑Z and digits 2‑7 are allowed.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Base32String;
///
/// let b32 = Base32String::new("JBSWY3DPEHPK3PXP")?;
/// assert_eq!(b32.as_str(), "JBSWY3DPEHPK3PXP");
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base32String(String);

impl Base32String {
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &s).is_some() {
            Ok(Base32String(s.to_uppercase()))
        } else {
            Err(AuthError::InvalidInput("Invalid base32 string".into()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_secret(&self) -> Result<Secret> {
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &self.0)
            .ok_or_else(|| AuthError::InvalidInput("Failed to decode base32".into()))?;
        Ok(Secret::new(decoded))
    }
}

/// TOTP time step in seconds.
///
/// Must be strictly positive.
///
/// # Default
/// `TimeStep::default()` returns 30 seconds.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::TimeStep;
///
/// let ts = TimeStep::new(30)?;
/// assert_eq!(ts.value(), 30);
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStep(u64);

impl TimeStep {
    pub fn new(step: u64) -> Result<Self> {
        if step == 0 {
            Err(AuthError::InvalidInput(
                "Time step must be greater than 0".into(),
            ))
        } else {
            Ok(TimeStep(step))
        }
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Default for TimeStep {
    fn default() -> Self {
        TimeStep(super::constants::DEFAULT_TIME_STEP)
    }
}

/// Number of digits for an OTP token.
///
/// Allowed range: 4 to 10 inclusive.
///
/// # Default
/// `Digits::default()` returns 6.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Digits;
///
/// let d = Digits::new(8)?;
/// assert_eq!(d.value(), 8);
/// # Ok::<(), libage_auth_handler::errors::AuthError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digits(u32);

impl Digits {
    pub fn new(n: u32) -> Result<Self> {
        if (4..=10).contains(&n) {
            Ok(Digits(n))
        } else {
            Err(AuthError::InvalidInput(
                "Digits must be between 4 and 10".into(),
            ))
        }
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

impl Default for Digits {
    fn default() -> Self {
        Digits(super::constants::DEFAULT_DIGITS)
    }
}

/// HOTP counter value (64‑bit unsigned).
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::Counter;
///
/// let mut c = Counter::new(0);
/// c.increment();
/// assert_eq!(c.value(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter(u64);

impl Counter {
    pub fn new(c: u64) -> Self {
        Counter(c)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

/// Ciphertext produced by [`crate::traits::CryptoBackend::encrypt`].
///
/// Wraps the encrypted bytes in `Zeroizing`, so the ciphertext is cleared
/// from memory when dropped.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::types::EncryptedPayload;
///
/// let payload = EncryptedPayload::new(b"encrypted data".to_vec());
/// assert_eq!(payload.as_bytes(), b"encrypted data");
/// ```
#[derive(Clone)]
pub struct EncryptedPayload(Zeroizing<Vec<u8>>);

impl EncryptedPayload {
    pub fn new(data: Vec<u8>) -> Self {
        EncryptedPayload(Zeroizing::new(data))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedPayload").finish()
    }
}

impl PartialEq for EncryptedPayload {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for EncryptedPayload {}

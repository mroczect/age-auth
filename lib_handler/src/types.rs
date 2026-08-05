use crate::errors::{AuthError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ==================== Recipient & Identity (sudah ada, diperketat) ====================

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

#[derive(Clone)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self {
        Secret(data)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token(u32);

impl Token {
    pub fn new(value: u32, digits: u32) -> Result<Self> {
        if digits == 0 || digits > 10 || value >= 10u32.pow(digits) {
            Err(AuthError::InvalidInput(
                "Token value does not match expected digits".into(),
            ))
        } else {
            Ok(Token(value))
        }
    }

    pub fn value(&self) -> u32 {
        self.0
    }

    pub fn format(&self, digits: u32) -> String {
        format!("{:0width$}", self.0, width = digits as usize)
    }
}

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
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPayload(Vec<u8>);

impl EncryptedPayload {
    pub fn new(data: Vec<u8>) -> Self {
        EncryptedPayload(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

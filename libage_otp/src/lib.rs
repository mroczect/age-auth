//! # libage_otp
//!
//! Pure Rust implementation of TOTP (RFC 6238) and HOTP (RFC 4226).
//!
//! This crate provides the [`AgeOtp`] struct, which implements the
//! [`OtpGenerator`] trait from [`libage_auth_handler`].
//! It is entirely independent of the age encryption layer – it only
//! deals with raw secrets and counters/timestamps.
//!
//! # Quick start
//!
//! ```rust
//! use libage_otp::AgeOtp;
//! use libage_auth_handler::traits::OtpGenerator;
//! use libage_auth_handler::types::{Secret, Digits, Counter, TimeStep};
//! use libage_auth_handler::Algo;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let secret = Secret::new(b"12345678901234567890".to_vec());
//!
//! // HOTP
//! let token = AgeOtp::hotp(&secret, Counter::new(0), Digits::new(6)?, Algo::Sha1)?;
//! println!("HOTP: {}", token.format(6));
//!
//! // TOTP (current time)
//! let token = AgeOtp::totp(&secret, TimeStep::default(), Digits::default(), Algo::Sha256)?;
//! println!("TOTP: {}", token.format(6));
//! # Ok(())
//! # }
//! ```

pub mod algorithms;

use libage_auth_handler::Algo;
use libage_auth_handler::errors::Result;
use libage_auth_handler::traits::OtpGenerator;
use libage_auth_handler::types::{Base32String, Counter, Digits, Secret, TimeStep, Token};

/// OTP generator implementing [`OtpGenerator`].
///
/// `AgeOtp` is a zero‑sized struct that delegates to the functions in
/// the [`algorithms`] module. All methods are associated functions
/// (they do not take `&self`), so they are called as `AgeOtp::totp(...)`.
///
/// # Security
///
/// - The secret is accessed only via `&[u8]` and never cloned.
/// - HMAC results are dropped immediately after truncation.
/// - No `unwrap`/`expect` is used on user input.
/// - The system clock is read once per call; clock errors are returned,
///   not panicked.
///
/// # Examples
///
/// ```rust
/// use libage_otp::AgeOtp;
/// use libage_auth_handler::traits::OtpGenerator;
/// use libage_auth_handler::types::{Secret, Counter, Digits};
/// use libage_auth_handler::Algo;
///
/// let secret = Secret::new(b"12345678901234567890".to_vec());
/// let token = AgeOtp::hotp(&secret, Counter::new(0), Digits::new(6).unwrap(), Algo::Sha1)
///     .expect("HOTP generation failed");
/// assert_eq!(token.format(6).len(), 6);
/// ```
pub struct AgeOtp;

impl OtpGenerator for AgeOtp {
    /// Generates a time‑based one‑time password (TOTP).
    ///
    /// Uses the current system time as the counter. For a deterministic
    /// version, use [`algorithms::compute_totp_at`] directly.
    ///
    /// # Parameters
    /// - `secret`: The shared secret.
    /// - `time_step`: Time step in seconds (must be > 0).
    /// - `digits`: Number of digits for the token (4‑10).
    /// - `algo`: HMAC algorithm ([`Algo::Sha1`], [`Algo::Sha256`], [`Algo::Sha512`]).
    ///
    /// # Errors
    /// Returns [`libage_auth_handler::errors::AuthError::Otp`] if the system clock is before the Unix
    /// epoch or the computed token exceeds the allowed range.
    ///
    /// # Example
    /// ```rust
    /// # use libage_otp::AgeOtp;
    /// # use libage_auth_handler::traits::OtpGenerator;
    /// # use libage_auth_handler::types::{Secret, TimeStep, Digits};
    /// # use libage_auth_handler::Algo;
    /// let secret = Secret::new(b"12345678901234567890".to_vec());
    /// let token = AgeOtp::totp(
    ///     &secret,
    ///     TimeStep::new(30).unwrap(),
    ///     Digits::new(6).unwrap(),
    ///     Algo::Sha256,
    /// ).expect("TOTP failed");
    /// assert_eq!(token.format(6).len(), 6);
    /// ```
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token> {
        let now = algorithms::current_unix_time()?;
        algorithms::compute_totp_at(secret, now, time_step, digits, algo)
    }

    /// Generates a counter‑based one‑time password (HOTP).
    ///
    /// See [`algorithms::compute_hotp_at`] for the underlying algorithm.
    ///
    /// # Parameters
    /// - `secret`: The shared secret.
    /// - `counter`: Counter value (8‑byte big‑endian integer internally).
    /// - `digits`: Number of digits for the token (4‑10).
    /// - `algo`: HMAC algorithm.
    ///
    /// # Errors
    /// Returns [`libage_auth_handler::errors::AuthError::Otp`] if the secret is invalid for the chosen
    /// algorithm or the computed token exceeds the allowed range.
    ///
    /// # Example
    /// ```rust
    /// # use libage_otp::AgeOtp;
    /// # use libage_auth_handler::traits::OtpGenerator;
    /// # use libage_auth_handler::types::{Secret, Counter, Digits};
    /// # use libage_auth_handler::Algo;
    /// let secret = Secret::new(b"12345678901234567890".to_vec());
    /// let token = AgeOtp::hotp(
    ///     &secret,
    ///     Counter::new(42),
    ///     Digits::new(8).unwrap(),
    ///     Algo::Sha256,
    /// ).expect("HOTP failed");
    /// assert_eq!(token.format(8).len(), 8);
    /// ```
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token> {
        algorithms::compute_hotp_at(secret, counter.value(), digits, algo)
    }

    /// Convenience method: decode a Base32‑encoded secret and return the
    /// current TOTP code using default parameters.
    ///
    /// Defaults: time step = **30s**, digits = **6**, algorithm = **SHA‑256**.
    ///
    /// # Parameters
    /// - `secret_base32`: A valid Base32‑encoded secret string (RFC 4648,
    ///   no padding).
    ///
    /// # Returns
    /// A formatted OTP string (e.g., `"123456"`).
    ///
    /// # Errors
    /// Returns `Err` if:
    /// - The Base32 string is invalid or cannot be decoded.
    /// - The system clock is before the Unix epoch.
    /// - The generated token exceeds 6 digits (should never occur).
    ///
    /// # Example
    /// ```rust
    /// # use libage_otp::AgeOtp;
    /// # use libage_auth_handler::traits::OtpGenerator;
    /// # use libage_auth_handler::types::Base32String;
    /// let base32 = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
    /// let code = AgeOtp::totp_now_from_base32(&base32).unwrap();
    /// assert_eq!(code.len(), 6);
    /// ```
    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String> {
        let secret = secret_base32.to_secret()?;
        let time_step = TimeStep::default();
        let digits = Digits::default();
        let token = Self::totp(&secret, time_step, digits, Algo::DEFAULT)?;
        Ok(token.format(digits.value()))
    }
}

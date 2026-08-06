//! Low‑level HOTP and TOTP algorithms (RFC 4226 / RFC 6238).
//!
//! This module provides the cryptographic core for the [`AgeOtp`](super::AgeOtp)
//! implementation. The public entry points are:
//!
//! * [`compute_hotp_at`] – counter‑based one‑time password (HOTP)
//! * [`compute_totp_at`] – time‑based one‑time password (TOTP)
//! * A private helper to obtain the current UNIX timestamp is used
//!   internally.
//!
//! All functions are deterministic and side‑effect free (except for
//! `current_unix_time` which reads the system clock).
//!
//! # Security
//! * Secret material is never cloned or logged – it is only accessed via
//!   `&[u8]`.
//! * HMAC results are dropped immediately after truncation.
//! * No `unwrap`/`expect` are used on user input.

use hmac::KeyInit;
use hmac::{Hmac, Mac};
use libage_auth_handler::Algo;
use libage_auth_handler::errors::{AuthError, Result};
#[cfg(test)]
use libage_auth_handler::types::Base32String;
use libage_auth_handler::types::{Digits, Secret, TimeStep, Token};

// ---------------------------------------------------------------------------
// Dynamic truncation (RFC 4226 §5.3)
// ---------------------------------------------------------------------------

/// Dynamic truncation as defined in RFC 4226, Section 5.3.
///
/// Takes the HMAC output and the desired number of digits, extracts a 31‑bit
/// value at the offset indicated by the last nibble of the HMAC, and returns
/// that value modulo `10^digits`.
///
/// This is an internal helper and not exposed publicly.
fn dynamic_truncate(hmac: &[u8], digits: u32) -> u64 {
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    let b1 = (hmac[offset] & 0x7f) as u64;
    let b2 = hmac[offset + 1] as u64;
    let b3 = hmac[offset + 2] as u64;
    let b4 = hmac[offset + 3] as u64;
    let binary = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    binary % 10u64.pow(digits)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute a counter‑based one‑time password (HOTP) according to RFC 4226.
///
/// # Parameters
/// * `secret` – the shared secret (arbitrary length).
/// * `counter` – the counter value (8‑byte big‑endian integer).
/// * `digits` – desired number of digits (4‑10). Must match the value
///   passed later to [`Token::format`].
/// * `algo` – the HMAC hash algorithm ([`Algo::Sha1`], [`Algo::Sha256`], or
///   [`Algo::Sha512`]).
///
/// # Returns
/// A [`Token`] containing the numeric HOTP value. The token can be formatted
/// with `token.format(digits.value())`.
///
/// # Errors
/// Returns [`AuthError::Otp`] if:
/// * The secret is not a valid key for the chosen HMAC algorithm.
/// * The computed token value exceeds the allowed range for the given
///   `digits` (this should never happen under normal operation).
///
/// # Example
/// ```rust
/// use libage_otp::algorithms::compute_hotp_at;
/// use libage_auth_handler::Algo;
/// use libage_auth_handler::types::{Secret, Digits};
///
/// let secret = Secret::new(b"12345678901234567890".to_vec());
/// let token = compute_hotp_at(&secret, 0, Digits::new(6).unwrap(), Algo::Sha1)
///     .expect("HOTP computation should succeed");
/// assert_eq!(token.value(), 755224);
/// ```
///
/// # References
/// * [RFC 4226 – HOTP: An HMAC‑Based One‑Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)
pub fn compute_hotp_at(secret: &Secret, counter: u64, digits: Digits, algo: Algo) -> Result<Token> {
    let counter_bytes = counter.to_be_bytes();
    let value = match algo {
        Algo::Sha1 => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
        Algo::Sha256 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
        Algo::Sha512 => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
    };
    Token::new(value, digits.value()).map_err(|e| AuthError::Otp(e.to_string()))
}

/// Compute a time‑based one‑time password (TOTP) according to RFC 6238.
///
/// TOTP is essentially HOTP with the counter derived from the current Unix
/// time: `counter = floor(timestamp / time_step)`.
///
/// # Parameters
/// * `secret` – the shared secret.
/// * `timestamp` – a Unix timestamp in **seconds**.
/// * `time_step` – the time step in seconds (must be > 0).
/// * `digits` – number of digits for the token (4‑10).
/// * `algo` – HMAC algorithm.
///
/// # Returns
/// A [`Token`] containing the TOTP value.
///
/// # Errors
/// Propagates errors from [`compute_hotp_at`].
///
/// # Example (deterministic timestamp)
/// ```rust
/// use libage_otp::algorithms::compute_totp_at;
/// use libage_auth_handler::Algo;
/// use libage_auth_handler::types::{Secret, TimeStep, Digits};
///
/// let secret = Secret::new(b"12345678901234567890".to_vec());
/// let token = compute_totp_at(
///     &secret,
///     1700000000,
///     TimeStep::new(30).unwrap(),
///     Digits::new(8).unwrap(),
///     Algo::Sha256,
/// ).expect("TOTP computation should succeed");
///
/// assert_eq!(token.format(8).len(), 8);
/// ```
///
/// # References
/// * [RFC 6238 – TOTP: Time‑Based One‑Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
pub fn compute_totp_at(
    secret: &Secret,
    timestamp: u64,
    time_step: TimeStep,
    digits: Digits,
    algo: Algo,
) -> Result<Token> {
    let steps = timestamp / time_step.value();
    compute_hotp_at(secret, steps, digits, algo)
}

/// Return the current Unix time in seconds.
///
/// # Errors
/// Returns [`AuthError::Otp`] if the system clock is set **before** the Unix
/// epoch (1970‑01‑01T00:00:00Z). This is extremely unlikely on modern
/// systems.
///
/// # Note
/// This function is `pub(crate)` – it is used internally by
/// [`AgeOtp::totp`](super::AgeOtp::totp) and not exposed to downstream
/// users.
pub(crate) fn current_unix_time() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AuthError::Otp("System clock before UNIX epoch".into()))
}

// ---------------------------------------------------------------------------
// Tests – RFC vectors and edge cases
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the RFC 4226 test secret "12345678901234567890" decoded from
    /// its base‑32 representation.
    fn rfc_secret() -> Secret {
        Base32String::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .to_secret()
            .unwrap()
    }

    #[test]
    fn hotp_rfc4226_vector_0() {
        let t = compute_hotp_at(&rfc_secret(), 0, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 755224);
    }
    #[test]
    fn hotp_rfc4226_vector_1() {
        let t = compute_hotp_at(&rfc_secret(), 1, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 287082);
    }
    #[test]
    fn hotp_rfc4226_vector_2() {
        let t = compute_hotp_at(&rfc_secret(), 2, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 359152);
    }
    #[test]
    fn hotp_8digit_vector_0() {
        let t = compute_hotp_at(&rfc_secret(), 0, Digits::new(8).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 84755224);
    }

    #[test]
    fn totp_sha1_vectors() {
        let s = Secret::new(b"12345678901234567890".to_vec());
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha1).unwrap().value(),
            94287082
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha1)
                .unwrap()
                .value(),
            7081804
        );
    }

    #[test]
    fn totp_sha256_vectors() {
        let s = Secret::new(b"12345678901234567890123456789012".to_vec());
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha256)
                .unwrap()
                .value(),
            46119246
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha256)
                .unwrap()
                .value(),
            68084774
        );
    }

    #[test]
    fn totp_sha512_vectors() {
        let s = Secret::new(
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
        );
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha512)
                .unwrap()
                .value(),
            90693936
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha512)
                .unwrap()
                .value(),
            25091201
        );
    }

    #[test]
    fn edge_case_short_secret_ok() {
        let secret = Secret::new(b"1234567890".to_vec());
        assert!(compute_hotp_at(&secret, 0, Digits::new(6).unwrap(), Algo::Sha1).is_ok());
    }
}

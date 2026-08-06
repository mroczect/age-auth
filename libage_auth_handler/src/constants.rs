//! Default values for TOTP/HOTP generation.
//!
//! These constants are used throughout the `age-auth` workspace as fallback
//! values when the caller does not explicitly provide a parameter.
//!
//! # Security considerations
//!
//! * `DEFAULT_ALGO` is set to `Algo::Sha256`. SHA‑1 is still available but
//!   must be chosen explicitly.
//! * `DEFAULT_DIGITS` is 6, which is the most common OTP length.
//! * `DEFAULT_TIME_STEP` is 30 seconds, the value used by virtually all
//!   TOTP implementations.

use super::enums::Algo;

/// Default time step (in seconds) for TOTP.
///
/// Value: `30`
pub const DEFAULT_TIME_STEP: u64 = 30;

/// Default number of digits for OTP tokens.
///
/// Value: `6`
pub const DEFAULT_DIGITS: u32 = 6;

/// Default hash algorithm for OTP generation.
///
/// Value: `Algo::Sha256`
pub const DEFAULT_ALGO: Algo = Algo::Sha256;

//! Hash algorithms supported by the OTP engine.
//!
//! The `Algo` enum lists every HMAC algorithm that can be used with
//! [`crate::traits::OtpGenerator::totp`] and [`crate::traits::OtpGenerator::hotp`].

use serde::{Deserialize, Serialize};

/// HMAC algorithm for OTP generation.
///
/// # Variants
/// - `Sha1`   – SHA‑1 (160‑bit). Legacy, not recommended for new deployments.
/// - `Sha256` – SHA‑256 (256‑bit). **Default** and recommended choice.
/// - `Sha512` – SHA‑512 (512‑bit). Strongest option, though no practical
///   security benefit over SHA‑256 for OTP.
///
/// # Serde
/// The enum derives `Serialize` and `Deserialize` so it can be used in
/// configuration files or API responses.
///
/// # Default
/// The default algorithm is `Sha256`. You can obtain it via `Algo::DEFAULT`
/// or `DEFAULT_ALGO` constant.
///
/// # Examples
/// ```rust
/// use libage_auth_handler::Algo;
///
/// let algo = Algo::DEFAULT;
/// assert_eq!(algo, Algo::Sha256);
/// ```

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algo {
    /// SHA‑1 (160‑bit). Provided for compatibility. Prefer `Sha256`.
    Sha1,
    /// SHA‑256 (256‑bit). **Default** algorithm.
    Sha256,
    /// SHA‑512 (512‑bit).
    Sha512,
}

impl Algo {
    /// The default hash algorithm used when none is specified.
    ///
    /// Currently returns `Algo::Sha256`.
    pub const DEFAULT: Algo = Algo::Sha256;
}

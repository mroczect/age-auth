//! Optional validation trait.
//!
//! Types can implement [`Validate`] to provide a custom consistency check
//! beyond what the constructor already guarantees. This is rarely needed
//! because all public types in this crate are validated at construction
//! time.

use crate::errors::Result;

/// Trait for types that support an explicit validation step.
///
/// # Notes
/// This trait is not used internally; it is provided for downstream
/// consumers who wish to add additional invariants to their own types.
pub trait Validate {
    /// Checks whether the value is valid according to its own rules.
    ///
    /// # Errors
    /// Returns `Err(AuthError::InvalidInput(...))` if validation fails.
    fn validate(&self) -> Result<()>;
}

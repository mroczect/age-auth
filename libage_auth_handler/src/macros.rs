//! Convenience macros for early error returns.
//!
//! This module exports two macros – `ensure!` and `bail!` – that make
//! input validation concise and consistent across the workspace. They return
//! `Err(AuthError::InvalidInput(...))` from the enclosing function, so they
//! can only be used inside functions that return `Result<_, AuthError>`.

/// Exits the function with an `InvalidInput` error if the condition is false.
///
/// # Usage
/// ```rust
/// # use libage_auth_handler::{ensure, AuthError};
/// # fn validate(input: &str, recipient: &str) -> Result<(), AuthError> {
/// ensure!(input.len() >= 8, "input too short");
/// ensure!(recipient.starts_with("age1"), AuthError::InvalidInput("bad recipient".to_string()));
/// # Ok(())
/// # }
/// ```
///
/// The first form takes a string literal; the second form takes any
/// expression that implements `Into<String>`.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($crate::errors::AuthError::InvalidInput($msg.into()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return Err($err.into());
        }
    };
}

/// Immediately exits the function with an error.
///
/// # Usage
/// ```rust
/// # use libage_auth_handler::{bail, AuthError};
/// # fn fail_with_message() -> Result<(), AuthError> {
/// bail!("something went wrong");
/// # }
/// #
/// # fn fail_with_error() -> Result<(), AuthError> {
/// # let my_error = AuthError::InvalidInput("bad".to_string());
/// bail!(my_error);
/// # }
/// ```
///
/// The first form takes a string literal and returns
/// `Err(AuthError::InvalidInput(...))`. The second form takes any
/// expression that implements `Into<AuthError>`.
#[macro_export]
macro_rules! bail {
    ($msg:literal $(,)?) => {
        return Err($crate::errors::AuthError::InvalidInput($msg.into()));
    };
    ($err:expr $(,)?) => {
        return Err($err.into());
    };
}

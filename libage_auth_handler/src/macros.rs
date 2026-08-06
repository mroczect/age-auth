//! Convenience macros for early error returns.
//!
//! This module exports two macros – `ensure!` and `bail!` – that make
//! input validation concise and consistent across the workspace. They return
//! `Err(AuthError::InvalidInput(...))` from the enclosing function, so they
//! can only be used inside functions that return `Result<_, AuthError>`.

/// Exits the function with an `InvalidInput` error if the condition is false.
///
/// # Usage
/// ```rust,ignore
/// ensure!(input.len() >= 8, "input too short");
/// ensure!(recipient.is_valid(), AuthError::InvalidInput("bad recipient"));
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
            return Err($crate::errors::AuthError::InvalidInput($err.into()));
        }
    };
}

/// Immediately exits the function with an error.
///
/// # Usage
/// ```rust,ignore
/// bail!("something went wrong");
/// bail!(my_error);
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

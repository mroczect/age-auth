use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("OTP error: {0}")]
    Otp(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unknown error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, AuthError>;

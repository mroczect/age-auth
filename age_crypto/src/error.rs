use lib_handler::errors::AuthError;

pub(crate) fn from_librage_error_body(body: &librage::ErrorBody) -> AuthError {
    match body.code.as_str() {
        "INVALID_PUBLIC_KEY" | "INVALID_SSH_KEY" | "INVALID_INPUT" => {
            AuthError::InvalidInput(body.message.clone())
        }
        "INVALID_SECRET_KEY" => AuthError::Crypto(format!("Invalid secret key: {}", body.message)),
        "IO_ERROR" => AuthError::Io(std::io::Error::other(body.message.clone())),
        _ => AuthError::Crypto(format!("{}: {}", body.code, body.message)),
    }
}

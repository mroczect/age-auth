use lib_handler::*;

#[test]
fn test_error_display() {
    let err = AuthError::InvalidInput("test".into());
    assert!(format!("{}", err).contains("test"));
}

#[test]
fn test_io_error_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let auth_err: AuthError = io_err.into();
    assert!(matches!(auth_err, AuthError::Io(_)));
}

#[test]
fn test_result_type() {
    let res: Result<()> = Err(AuthError::Otp("bad".into()));
    assert!(res.is_err());
}

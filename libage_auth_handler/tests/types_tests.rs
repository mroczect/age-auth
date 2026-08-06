use libage_auth_handler::*;

#[test]
fn test_recipient_valid() {
    let r = Recipient::new("age1abc123").unwrap();
    assert_eq!(r.as_str(), "age1abc123");
}

#[test]
fn test_recipient_invalid_prefix() {
    assert!(Recipient::new("invalid").is_err());
}

#[test]
fn test_recipient_invalid_short() {
    assert!(Recipient::new("age1").is_err());
}

#[test]
fn test_identity_valid() {
    let i = Identity::new("AGE-SECRET-KEY-12345678901234567890").unwrap();
    assert!(i.as_str().starts_with("AGE-SECRET-KEY-"));
}

#[test]
fn test_identity_invalid() {
    assert!(Identity::new("wrong").is_err());
}

#[test]
fn test_secret_zeroize_on_drop() {
    let data = vec![1, 2, 3];
    let secret = Secret::new(data.clone());
    drop(secret);
}

#[test]
fn test_secret_len() {
    let s = Secret::new(vec![1, 2, 3]);
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
}

#[test]
fn test_secret_empty() {
    let s = Secret::new(vec![]);
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

#[test]
fn test_token_valid() {
    let t = Token::new(123456, 6).unwrap();
    assert_eq!(t.value(), 123456);
    assert_eq!(t.format(6), "123456");
}

#[test]
fn test_token_boundary_4_digits() {
    let t = Token::new(9999, 4).unwrap();
    assert_eq!(t.format(4), "9999");
    assert!(Token::new(10000, 4).is_err());
}

#[test]
fn test_token_boundary_10_digits() {
    let t = Token::new(9_999_999_999, 10).unwrap();
    assert_eq!(t.format(10), "9999999999");
    assert!(Token::new(10_000_000_000, 10).is_err());
}

#[test]
fn test_token_invalid_zero_digits() {
    assert!(Token::new(0, 0).is_err());
}

#[test]
fn test_base32string_valid() {
    let b = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(b.as_str(), "JBSWY3DPEHPK3PXP");
}

#[test]
fn test_base32string_invalid() {
    assert!(Base32String::new("!!!!").is_err());
}

#[test]
fn test_base32string_to_secret() {
    let b = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
    let secret = b.to_secret().unwrap();
    assert!(!secret.is_empty());
    assert_eq!(secret.as_bytes().len(), 10);
}

#[test]
fn test_time_step_valid() {
    let ts = TimeStep::new(30).unwrap();
    assert_eq!(ts.value(), 30);
    assert_eq!(TimeStep::default().value(), 30);
}

#[test]
fn test_time_step_invalid() {
    assert!(TimeStep::new(0).is_err());
}

#[test]
fn test_digits_valid() {
    let d = Digits::new(4).unwrap();
    assert_eq!(d.value(), 4);
    let d10 = Digits::new(10).unwrap();
    assert_eq!(d10.value(), 10);
}

#[test]
fn test_digits_invalid() {
    assert!(Digits::new(3).is_err());
    assert!(Digits::new(11).is_err());
}

#[test]
fn test_counter_increment() {
    let mut c = Counter::new(0);
    assert_eq!(c.value(), 0);
    c.increment();
    assert_eq!(c.value(), 1);
}

#[test]
fn test_encrypted_payload() {
    let data = vec![1, 2, 3];
    let p = EncryptedPayload::new(data.clone());
    assert_eq!(p.as_bytes(), &data);
}

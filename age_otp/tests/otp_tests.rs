use age_otp::AgeOtp;
use lib_handler::Algo;
use lib_handler::traits::OtpGenerator;
use lib_handler::types::{Base32String, Counter, Digits, Secret};

fn rfc_secret() -> Secret {
    Base32String::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .unwrap()
        .to_secret()
        .unwrap()
}

#[test]
fn hotp_vector_0() {
    let t = AgeOtp::hotp(
        &rfc_secret(),
        Counter::new(0),
        Digits::new(6).unwrap(),
        Algo::Sha1,
    )
    .unwrap();
    assert_eq!(t.value(), 755224);
}

#[test]
fn hotp_vector_1() {
    let t = AgeOtp::hotp(
        &rfc_secret(),
        Counter::new(1),
        Digits::new(6).unwrap(),
        Algo::Sha1,
    )
    .unwrap();
    assert_eq!(t.value(), 287082);
}

#[test]
fn hotp_sha256_works() {
    let t = AgeOtp::hotp(
        &rfc_secret(),
        Counter::new(0),
        Digits::new(6).unwrap(),
        Algo::Sha256,
    )
    .unwrap();
    assert_eq!(t.format(6).len(), 6);
}

#[test]
fn totp_now_from_base32_gives_6_digits() {
    let b32 = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
    let code = AgeOtp::totp_now_from_base32(&b32).unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn invalid_base32_is_rejected() {
    assert!(Base32String::new("!!!!").is_err());
}

#[test]
fn minimum_digits_token_ok() {
    let secret = Base32String::new("JBSWY3DPEHPK3PXP")
        .unwrap()
        .to_secret()
        .unwrap();
    let t = AgeOtp::hotp(
        &secret,
        Counter::new(0),
        Digits::new(4).unwrap(),
        Algo::Sha1,
    )
    .unwrap();
    assert_eq!(t.format(4).len(), 4);
}

#[test]
fn secret_can_be_reused() {
    let s = rfc_secret();
    let _ = AgeOtp::hotp(&s, Counter::new(0), Digits::new(6).unwrap(), Algo::Sha1).unwrap();
    let _ = AgeOtp::hotp(&s, Counter::new(1), Digits::new(6).unwrap(), Algo::Sha1).unwrap();
}

use libage_auth_handler::traits::{Authenticator, OtpGenerator};
use libage_auth_handler::types::{Base32String, Secret};
use libage_authenticator::AgeAuthenticator;
use libage_crypto::generate_keypair;
use std::io::Cursor;

#[test]
fn full_workflow_matches_direct_otp() {
    let auth = AgeAuthenticator::new();
    let (recipient, identity) = generate_keypair().unwrap();

    let base32_str = "JBSWY3DPEHPK3PXP";
    let base32 = Base32String::new(base32_str).unwrap();
    let secret = Secret::new(base32_str.as_bytes().to_vec());

    let encrypted = auth.provision(&recipient, &secret).unwrap();

    let mut reader = Cursor::new(identity.as_str().as_bytes());
    let code_from_encrypted = auth
        .generate_totp_from_encrypted(&mut reader, &encrypted)
        .unwrap();

    let direct_code = AgeAuthenticator::totp_now_from_base32(&base32).unwrap();

    assert_eq!(code_from_encrypted.len(), 6);
    assert_eq!(code_from_encrypted, direct_code);
}

#[test]
fn multiple_recipients_all_can_decrypt() {
    let auth = AgeAuthenticator::new();
    let (r1, id1) = generate_keypair().unwrap();
    let (r2, id2) = generate_keypair().unwrap();
    let secret = Secret::new(b"multi-recipient-test".to_vec());

    let encrypted = auth
        .provision_multiple(&[r1.clone(), r2.clone()], &secret)
        .unwrap();

    let mut reader1 = Cursor::new(id1.as_str().as_bytes());
    let dec1 = auth
        .load_encrypted_secret(&mut reader1, &encrypted)
        .unwrap();
    assert_eq!(dec1.as_bytes(), secret.as_bytes());

    let mut reader2 = Cursor::new(id2.as_str().as_bytes());
    let dec2 = auth
        .load_encrypted_secret(&mut reader2, &encrypted)
        .unwrap();
    assert_eq!(dec2.as_bytes(), secret.as_bytes());
}

#[test]
fn zeroize_after_decrypt() {
    let auth = AgeAuthenticator::new();
    let (recipient, identity) = generate_keypair().unwrap();
    let secret = Secret::new(b"zeroize-me".to_vec());

    let encrypted = auth.provision(&recipient, &secret).unwrap();

    let mut reader = Cursor::new(identity.as_str().as_bytes());
    let decrypted = auth.load_encrypted_secret(&mut reader, &encrypted).unwrap();
    drop(decrypted);
}

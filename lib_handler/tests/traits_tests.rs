use lib_handler::*;
use std::io::Read;

struct Dummy;

impl CryptoBackend for Dummy {
    fn encrypt(&self, _: &Recipient, _: &Secret) -> Result<EncryptedPayload> {
        Ok(EncryptedPayload::new(vec![1, 2, 3]))
    }
    fn decrypt(&self, _: &Identity, _: &EncryptedPayload) -> Result<Secret> {
        Ok(Secret::new(vec![4, 5, 6]))
    }
}

impl OtpGenerator for Dummy {
    fn totp(_: &Secret, _: TimeStep, _: Digits, _: Algo) -> Result<Token> {
        Ok(Token::new(123456, 6).unwrap())
    }
    fn hotp(_: &Secret, _: Counter, _: Digits, _: Algo) -> Result<Token> {
        Ok(Token::new(654321, 6).unwrap())
    }
    fn totp_now_from_base32(_: &Base32String) -> Result<String> {
        Ok("123456".into())
    }
}

impl Authenticator for Dummy {
    fn load_encrypted_secret(
        &self,
        _reader: &mut dyn Read,
        _encrypted: &EncryptedPayload,
    ) -> Result<Secret> {
        Ok(Secret::new(vec![7, 8, 9]))
    }

    fn generate_totp_from_encrypted(
        &self,
        _reader: &mut dyn Read,
        _encrypted: &EncryptedPayload,
    ) -> Result<String> {
        Ok("111111".into())
    }
}

#[test]
fn test_provision_default() {
    let dummy = Dummy;
    let recipient = Recipient::new("age1abcdef").unwrap();
    let secret = Secret::new(b"test".to_vec());
    let encrypted = dummy.provision(&recipient, &secret).unwrap();
    assert_eq!(encrypted.as_bytes(), &[1, 2, 3]);
}

#[test]
fn test_load_encrypted_secret() {
    let dummy = Dummy;
    let mut reader = std::io::Cursor::new(b"dummy identity");
    let encrypted = EncryptedPayload::new(vec![]);
    let secret = dummy
        .load_encrypted_secret(&mut reader, &encrypted)
        .unwrap();
    assert_eq!(secret.as_bytes(), &[7, 8, 9]);
}

#[test]
fn test_generate_totp_from_encrypted() {
    let dummy = Dummy;
    let mut reader = std::io::Cursor::new(b"dummy identity");
    let encrypted = EncryptedPayload::new(vec![]);
    let code = dummy
        .generate_totp_from_encrypted(&mut reader, &encrypted)
        .unwrap();
    assert_eq!(code, "111111");
}

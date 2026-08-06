use libage_auth_handler::errors::{AuthError, Result};
use libage_auth_handler::traits::{Authenticator, CryptoBackend, OtpGenerator};
use libage_auth_handler::types::{
    Base32String, Counter, Digits, EncryptedPayload, Identity, Recipient, Secret, TimeStep, Token,
};
use libage_crypto::AgeCrypto;
use libage_otp::AgeOtp;
use std::io::Read;
use zeroize::Zeroizing;

pub struct AgeAuthenticator {
    crypto: AgeCrypto,
}

impl AgeAuthenticator {
    pub fn new() -> Self {
        Self { crypto: AgeCrypto }
    }

    pub fn provision_multiple(
        &self,
        recipients: &[Recipient],
        secret: &Secret,
    ) -> Result<EncryptedPayload> {
        libage_crypto::encrypt_multiple(recipients, secret)
    }
}

impl Default for AgeAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoBackend for AgeAuthenticator {
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret) -> Result<EncryptedPayload> {
        self.crypto.encrypt(recipient, plaintext)
    }

    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload) -> Result<Secret> {
        self.crypto.decrypt(identity, ciphertext)
    }
}

impl OtpGenerator for AgeAuthenticator {
    fn totp(
        secret: &Secret,
        time_step: TimeStep,
        digits: Digits,
        algo: libage_auth_handler::Algo,
    ) -> Result<Token> {
        AgeOtp::totp(secret, time_step, digits, algo)
    }

    fn hotp(
        secret: &Secret,
        counter: Counter,
        digits: Digits,
        algo: libage_auth_handler::Algo,
    ) -> Result<Token> {
        AgeOtp::hotp(secret, counter, digits, algo)
    }

    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String> {
        AgeOtp::totp_now_from_base32(secret_base32)
    }
}
impl Authenticator for AgeAuthenticator {
    fn load_encrypted_secret(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret> {
        let mut identity_str = Zeroizing::new(String::new());
        identity_reader
            .read_to_string(&mut identity_str)
            .map_err(AuthError::Io)?;
        let identity = Identity::new(identity_str.as_str())?;
        self.crypto.decrypt(&identity, encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libage_auth_handler::types::Base32String;
    use libage_crypto::generate_keypair;

    #[test]
    fn full_provision_and_verification_flow() {
        let auth = AgeAuthenticator::new();
        let (recipient, identity) = generate_keypair().unwrap();

        let base32 = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
        let secret_bytes = Secret::new(base32.as_str().as_bytes().to_vec());

        let encrypted = auth.provision(&recipient, &secret_bytes).unwrap();

        let mut identity_reader = std::io::Cursor::new(identity.as_str().as_bytes());

        let decrypted_secret = auth
            .load_encrypted_secret(&mut identity_reader, &encrypted)
            .unwrap();

        assert_eq!(decrypted_secret.as_bytes(), secret_bytes.as_bytes());

        let decrypted_str = std::str::from_utf8(decrypted_secret.as_bytes()).unwrap();
        let base32_from_decrypted = Base32String::new(decrypted_str).unwrap();

        let code = <AgeAuthenticator as OtpGenerator>::totp_now_from_base32(&base32_from_decrypted)
            .unwrap();

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn wrong_identity_should_fail() {
        let auth = AgeAuthenticator::new();
        let (recipient, _) = generate_keypair().unwrap();
        let (_, wrong_identity) = generate_keypair().unwrap();
        let secret = Secret::new(b"super secret".to_vec());

        let encrypted = auth.provision(&recipient, &secret).unwrap();

        let mut reader = std::io::Cursor::new(wrong_identity.as_str().as_bytes());
        let result = auth.load_encrypted_secret(&mut reader, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn provision_multiple_recipients_works() {
        let auth = AgeAuthenticator::new();
        let (r1, id1) = generate_keypair().unwrap();
        let (r2, _) = generate_keypair().unwrap();
        let secret = Secret::new(b"multi".to_vec());

        let encrypted = auth.provision_multiple(&[r1.clone(), r2], &secret).unwrap();

        let mut reader = std::io::Cursor::new(id1.as_str().as_bytes());
        let decrypted = auth.load_encrypted_secret(&mut reader, &encrypted).unwrap();
        assert_eq!(decrypted.as_bytes(), b"multi");
    }

    #[test]
    fn generate_totp_from_encrypted_default_impl() {
        let auth = AgeAuthenticator::new();
        let (recipient, identity) = generate_keypair().unwrap();

        let base32_str = "JBSWY3DPEHPK3PXP";
        let secret = Secret::new(base32_str.as_bytes().to_vec());

        let encrypted = auth.provision(&recipient, &secret).unwrap();

        let mut reader = std::io::Cursor::new(identity.as_str().as_bytes());
        let code = auth
            .generate_totp_from_encrypted(&mut reader, &encrypted)
            .unwrap();
        assert_eq!(code.len(), 6);
    }

    #[test]
    fn load_encrypted_secret_zeroizes_identity_buffer() {
        let auth = AgeAuthenticator::new();
        let (recipient, identity) = generate_keypair().unwrap();
        let secret = Secret::new(b"zeroize test".to_vec());
        let encrypted = auth.provision(&recipient, &secret).unwrap();

        let mut reader = std::io::Cursor::new(identity.as_str().as_bytes());
        let _ = auth.load_encrypted_secret(&mut reader, &encrypted).unwrap();
    }
}

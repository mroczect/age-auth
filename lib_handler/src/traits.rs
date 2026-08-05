use crate::enums::Algo;
use crate::errors::Result;
use crate::types::{
    Base32String, Counter, Digits, EncryptedPayload, Identity, Recipient, Secret, TimeStep, Token,
};
use std::io::Read;

pub trait CryptoBackend {
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret) -> Result<EncryptedPayload>;

    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload) -> Result<Secret>;
}

pub trait OtpGenerator {
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token>;
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token>;
    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String>;
}

pub trait Authenticator: CryptoBackend + OtpGenerator {
    fn provision(&self, public_key: &Recipient, secret: &Secret) -> Result<EncryptedPayload> {
        self.encrypt(public_key, secret)
    }

    fn load_encrypted_secret(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret>;

    fn generate_totp_from_encrypted(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<String> {
        let secret = self.load_encrypted_secret(identity_reader, encrypted)?;
        let secret_str = std::str::from_utf8(secret.as_bytes()).map_err(|_| {
            crate::errors::AuthError::InvalidInput("Secret is not valid UTF-8".into())
        })?;
        let base32 = Base32String::new(secret_str)?;
        Self::totp_now_from_base32(&base32)
    }
}

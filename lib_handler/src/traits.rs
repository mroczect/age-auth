use crate::enums::Algo;
use crate::errors::Result;
use crate::types::{
    Base32String, Counter, Digits, EncryptedPayload, Identity, Recipient, Secret, TimeStep, Token,
};

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
        identity_path: &str,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret>;

    fn generate_totp_from_encrypted_file(
        &self,
        identity_path: &str,
        encrypted_path: &str,
    ) -> Result<String>;
}

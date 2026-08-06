use libage_auth_handler::errors::{AuthError, Result};
use libage_auth_handler::traits::CryptoBackend;
use libage_auth_handler::types::{EncryptedPayload, Identity, Recipient, Secret};

mod error;

pub struct AgeCrypto;

impl CryptoBackend for AgeCrypto {
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret) -> Result<EncryptedPayload> {
        let response = librage::encrypt(plaintext.as_bytes(), recipient.as_str());

        if response.success {
            let mut output = response
                .data
                .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
            let ciphertext = std::mem::take(&mut *output.ciphertext);
            Ok(EncryptedPayload::new(ciphertext))
        } else {
            let err_body = response
                .error
                .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
            Err(error::from_librage_error_body(&err_body))
        }
    }

    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload) -> Result<Secret> {
        let response = librage::decrypt(ciphertext.as_bytes(), identity.as_str());

        if response.success {
            let mut output = response
                .data
                .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
            let plaintext = std::mem::take(&mut *output.plaintext);
            Ok(Secret::new(plaintext))
        } else {
            let err_body = response
                .error
                .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
            Err(error::from_librage_error_body(&err_body))
        }
    }
}

pub fn encrypt_multiple(recipients: &[Recipient], secret: &Secret) -> Result<EncryptedPayload> {
    let keys: Vec<&str> = recipients.iter().map(|r| r.as_str()).collect();
    let response = librage::encrypt_multiple(secret.as_bytes(), &keys);

    if response.success {
        let mut output = response
            .data
            .ok_or_else(|| AuthError::Crypto("librage returned success but no data".into()))?;
        let ciphertext = std::mem::take(&mut *output.ciphertext);
        Ok(EncryptedPayload::new(ciphertext))
    } else {
        let err_body = response
            .error
            .ok_or_else(|| AuthError::Crypto("librage returned failure but no error".into()))?;
        Err(error::from_librage_error_body(&err_body))
    }
}

pub fn generate_keypair() -> Result<(Recipient, Identity)> {
    let kp = librage::generate_keypair();
    if !kp.success {
        let err_body = kp
            .error
            .ok_or_else(|| AuthError::Crypto("keygen failed without error body".into()))?;
        return Err(error::from_librage_error_body(&err_body));
    }

    let data = kp
        .data
        .ok_or_else(|| AuthError::Crypto("keygen succeeded without data".into()))?;
    let recipient = Recipient::new(data.public_key)
        .map_err(|e| AuthError::Crypto(format!("Invalid public key from keygen: {}", e)))?;
    let identity = Identity::new(data.secret_key.as_str())
        .map_err(|e| AuthError::Crypto(format!("Invalid secret key from keygen: {}", e)))?;

    Ok((recipient, identity))
}

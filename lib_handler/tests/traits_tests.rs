use lib_handler::*;

struct Dummy;

impl CryptoBackend for Dummy {
    fn encrypt(&self, _: &Recipient, _: &Secret) -> Result<EncryptedPayload> {
        unimplemented!()
    }
    fn decrypt(&self, _: &Identity, _: &EncryptedPayload) -> Result<Secret> {
        unimplemented!()
    }
}

impl OtpGenerator for Dummy {
    fn totp(_: &Secret, _: TimeStep, _: Digits, _: Algo) -> Result<Token> {
        unimplemented!()
    }
    fn hotp(_: &Secret, _: Counter, _: Digits, _: Algo) -> Result<Token> {
        unimplemented!()
    }
    fn totp_now_from_base32(_: &Base32String) -> Result<String> {
        unimplemented!()
    }
}

impl Authenticator for Dummy {
    fn load_encrypted_secret(&self, _: &str, _: &EncryptedPayload) -> Result<Secret> {
        unimplemented!()
    }
    fn generate_totp_from_encrypted_file(&self, _: &str, _: &str) -> Result<String> {
        unimplemented!()
    }
}

#[test]
fn test_trait_implementability() {
    let _d = Dummy;
}

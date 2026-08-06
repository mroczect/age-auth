# libage_authenticator

High-level authenticator combining age encryption and OTP generation.  
This crate provides the `AgeAuthenticator` type that ties together `libage_crypto` and `libage_otp` to implement the full `Authenticator` trait.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [`AgeAuthenticator`](#ageauthenticator)
  - [`Authenticator` trait](#authenticator-trait)
  - [`CryptoBackend` trait](#cryptobackend-trait)
  - [`OtpGenerator` trait](#otpgenerator-trait)
  - [Additional methods](#additional-methods)
- [Benchmarks](#benchmarks)
- [Security](#security)
- [License](#license)

## Features

- Complete implementation of `Authenticator`, `CryptoBackend`, and `OtpGenerator`.
- Encrypt OTP secrets to one or multiple age recipients.
- Decrypt and generate TOTP codes in a single call (`generate_totp_from_encrypted`).
- Identity handling via `std::io::Read` (supports files, network streams, etc.) with zeroized buffers.
- Helper to provision a secret for multiple recipients (`provision_multiple`).
- Benchmarks for provision, decryption, and full TOTP generation pipeline.

## Installation

```toml
[dependencies]
libage_authenticator = { path = "../libage_authenticator" }
```

```toml
[dependencies]
libage_authenticator = "0.1"
```

## Quick Start

```rust
use libage_authenticator::AgeAuthenticator;
use libage_crypto::generate_keypair;
use libage_auth_handler::traits::Authenticator;
use libage_auth_handler::types::Secret;
use std::io::Cursor;

// Create an authenticator instance
let auth = AgeAuthenticator::new();

// Generate a keypair
let (recipient, identity) = generate_keypair().unwrap();

// Provision a secret
let secret = Secret::new(b"JBSWY3DPEHPK3PXP".to_vec());
let encrypted = auth.provision(&recipient, &secret).unwrap();

// Later, decrypt the secret and generate a TOTP code
let mut identity_reader = Cursor::new(identity.as_str().as_bytes());
let totp_code = auth.generate_totp_from_encrypted(&mut identity_reader, &encrypted).unwrap();
println!("TOTP code: {}", totp_code);
```

## API Reference

### `AgeAuthenticator`

The main struct that combines age encryption and OTP generation.

```rust
pub struct AgeAuthenticator { /* fields */ }

impl AgeAuthenticator {
    pub fn new() -> Self;
    pub fn provision_multiple(
        &self,
        recipients: &[Recipient],
        secret: &Secret,
    ) -> Result<EncryptedPayload>;
}
```

#### `new`

Creates a new `AgeAuthenticator`.

#### `provision_multiple`

Encrypts a `secret` for **multiple** recipients. The resulting `EncryptedPayload` can be decrypted with any of the corresponding identities.

```rust
let (r1, id1) = generate_keypair()?;
let (r2, _)   = generate_keypair()?;
let secret = Secret::new(b"multi‑recipient".to_vec());

let encrypted = auth.provision_multiple(&[r1, r2], &secret)?;
let decrypted = auth.decrypt(&id1, &encrypted)?;
assert_eq!(decrypted.as_bytes(), secret.as_bytes());
```

### `Authenticator` trait

Implemented by `AgeAuthenticator`.

```rust
pub trait Authenticator: CryptoBackend + OtpGenerator {
    fn provision(&self, public_key: &Recipient, secret: &Secret)
        -> Result<EncryptedPayload>;
    fn load_encrypted_secret(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret>;
    fn generate_totp_from_encrypted(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<String>;
}
```

#### `provision`

Encrypts `secret` with `public_key` and returns the ciphertext.  
This method has a default implementation that delegates to `CryptoBackend::encrypt`.

#### `load_encrypted_secret`

Reads an identity string from `identity_reader`, uses it to decrypt `encrypted`, and returns the original `Secret`.  
The identity string is read into a `Zeroizing<String>` to prevent lingering in memory.

#### `generate_totp_from_encrypted`

Decrypts the secret via `load_encrypted_secret`, interprets it as a UTF‑8 Base32 string, decodes it, and returns the current TOTP code (6 digits, SHA‑256, 30s step).  
This is a convenience method with a default implementation.

### `CryptoBackend` trait

```rust
impl CryptoBackend for AgeAuthenticator {
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret)
        -> Result<EncryptedPayload>;
    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload)
        -> Result<Secret>;
}
```

Delegates directly to `AgeCrypto` (from `libage_crypto`). See that crate's README for details.

### `OtpGenerator` trait

```rust
impl OtpGenerator for AgeAuthenticator {
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo)
        -> Result<Token>;
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo)
        -> Result<Token>;
    fn totp_now_from_base32(secret_base32: &Base32String)
        -> Result<String>;
}
```

Delegates directly to `AgeOtp` (from `libage_otp`). See that crate's README for details.

### Additional methods

#### `provision_multiple`

```rust
pub fn provision_multiple(
    &self,
    recipients: &[Recipient],
    secret: &Secret,
) -> Result<EncryptedPayload>
```

Encrypts `secret` for every recipient in `recipients`. Internally calls `libage_crypto::encrypt_multiple`.

## Benchmarks

Benchmarks are provided for the three main operations:

- `provision` – encrypt a small secret
- `load_encrypted_secret` – decrypt a previously encrypted payload
- `generate_totp_from_encrypted` – full pipeline (decrypt + base32 decode + TOTP)

Run them with:

```bash
cargo bench --bench authenticator_benchmark
```

Results are written to `target/criterion/`.

## Security

- **Zeroize**: The identity string read during `load_encrypted_secret` is stored in a `Zeroizing<String>`. After decryption, both the ciphertext (already zeroized by `EncryptedPayload`) and the plaintext (zeroized by `Secret`) are cleared.
- **No panics**: All error paths use `Result` and never call `unwrap`/`expect` in production code.
- **Key management**: Private keys are never stored inside `AgeAuthenticator` – they are provided each time by the caller via `identity_reader`, giving the user full control over key storage.

## License

MIT – see `LICENSE` for details.

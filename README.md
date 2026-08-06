# age-auth

[![CI](https://github.com/mroczect/age-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/mroczect/age-auth/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Offline authenticator + OTP library secured by age encryption.**

`age-auth` is a Rust workspace that provides building blocks for creating
offline, time‑based or counter‑based one‑time password (OTP) systems
protected by [age](https://age-encryption.org) public‑key encryption.

Think of it as a toolbox to build your own offline authenticator app (like
Google Authenticator) but with the secret **always encrypted** at rest using
strong X25519 cryptography.

## Workspace structure

```
age-auth/                     (workspace root)
├── age_auth/                 (root crate – re‑exports everything)
├── libage_auth_handler/      (traits, types, errors)
├── libage_crypto/            (age encryption via librage)
├── libage_otp/               (TOTP/HOTP engine)
└── libage_authenticator/     (combines crypto + OTP, high‑level API)
```

You can depend on the workspace root crate (`age-auth`) to get everything,
or pick individual crates if you only need part of the functionality.

## Installation

Add the workspace root crate to your `Cargo.toml`:

```toml
[dependencies]
age-auth = "0.1"
```

Or depend on a specific component:

```toml
[dependencies]
libage_otp = "0.1"
libage_crypto = "0.1"
```

## Quick start

Here's a complete offline authenticator flow: generate a keypair, encrypt a
base32 secret, and later decrypt it to obtain a TOTP code.

```rust
use age_auth::{
    AgeAuthenticator, generate_keypair,
    traits::Authenticator,
    types::Secret,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create the authenticator
    let auth = AgeAuthenticator::new();

    // 2. Generate a keypair (the user would do this offline)
    let (recipient, identity) = generate_keypair()?;

    // 3. Provision a base32 secret
    let base32_secret = "JBSWY3DPEHPK3PXP"; // example OTP secret
    let secret = Secret::new(base32_secret.as_bytes().to_vec());
    let encrypted = auth.provision(&recipient, &secret)?;

    // 4. Later, when the user needs a TOTP code:
    let mut identity_reader = Cursor::new(identity.as_str().as_bytes());
    let totp_code = auth.generate_totp_from_encrypted(
        &mut identity_reader,
        &encrypted,
    )?;

    println!("Your one‑time code is: {}", totp_code);
    Ok(())
}
```

## API overview

All public items from the sub‑crates are re‑exported at the workspace root,
so you can import everything from `age_auth`:

- **Traits & types**: `Authenticator`, `CryptoBackend`, `OtpGenerator`,
  `Recipient`, `Identity`, `Secret`, `Token`, `Base32String`, `TimeStep`,
  `Digits`, `Counter`, `EncryptedPayload`, `Algo`, `AuthError`, etc.
- **Backend**: `AgeCrypto` – lightweight age encryption/decryption.
- **OTP engine**: `AgeOtp` – pure TOTP/HOTP implementation.
- **High‑level authenticator**: `AgeAuthenticator` – combines the above with
  convenient methods like `provision`, `load_encrypted_secret`, and
  `generate_totp_from_encrypted`.

Refer to the individual crate READMEs for detailed API documentation:

- [`libage_auth_handler`](libage_auth_handler/README.md)
- [`libage_crypto`](libage_crypto/README.md)
- [`libage_otp`](libage_otp/README.md)
- [`libage_authenticator`](libage_authenticator/README.md)

## Security

- Secrets are zeroized on drop (via the `zeroize` crate).
- No unwrap/expect in production code; all errors are propagated.
- Default OTP algorithm is SHA‑256, not SHA‑1.
- Identity material is never stored inside the library; the caller controls
  how and where keys are kept.

## License

MIT – see [LICENSE](LICENSE) for details.

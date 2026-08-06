# libage_auth_handler

Core traits, error types, and foundational handlers for the age-auth workspace.  
This crate provides the contracts and building blocks for offline authenticators secured by age encryption.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Enums](#enums)
    - [`Algo`](#algo)
  - [Types](#types)
    - [`Recipient`](#recipient)
    - [`Identity`](#identity)
    - [`Secret`](#secret)
    - [`Token`](#token)
    - [`Base32String`](#base32string)
    - [`TimeStep`](#timestep)
    - [`Digits`](#digits)
    - [`Counter`](#counter)
    - [`EncryptedPayload`](#encryptedpayload)
  - [Traits](#traits)
    - [`CryptoBackend`](#cryptobackend)
    - [`OtpGenerator`](#otpgenerator)
    - [`Authenticator`](#authenticator)
    - [`Validate`](#validate)
  - [Error Handling](#error-handling)
    - [`AuthError`](#autherror)
    - [`Result`](#result)
  - [Macros](#macros)
    - [`ensure!`](#ensure)
    - [`bail!`](#bail)
  - [Constants](#constants)
- [Safety & Security](#safety--security)
- [License](#license)

## Overview

`libage_auth_handler` defines the core abstractions used throughout the `age-auth` ecosystem.  
It provides strongly typed wrappers that enforce validation at construction time, automatic zeroization of sensitive data, and a unified error type.

All crates in the workspace (`libage_crypto`, `libage_otp`, `libage_authenticator`) depend on this crate to implement the contracts.

## Features

- **Strong typing** – every cryptographic parameter (recipient, identity, secret, digits, time step, etc.) is wrapped in a validated newtype.
- **Zeroize** – `Secret` and `EncryptedPayload` automatically clear their memory on drop.
- **Trait‑based design** – swap out the encryption backend or OTP algorithm without affecting the rest of the system.
- **Unified error handling** – a single `AuthError` enum with automatic conversions from `std::io::Error`.
- **Helpful macros** – `ensure!` and `bail!` for ergonomic validation.
- **Serde support** – all public types implement `Serialize` / `Deserialize` where appropriate.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
libage_auth_handler = { path = "../libage_auth_handler" }
```

```toml
[dependencies]
libage_auth_handler = "0.1"
```

## Quick Start

```rust
use libage_auth_handler::{
    Recipient, Identity, Secret, Base32String, Token, Digits, TimeStep, Counter,
    Algo, CryptoBackend, OtpGenerator, AuthError, ensure,
};

// Create a valid recipient (age public key)
let recipient = Recipient::new("age1...").expect("valid recipient");

// Create an identity (age secret key)
let identity = Identity::new("AGE-SECRET-KEY-...").expect("valid identity");

// Create a secret (will be zeroized on drop)
let secret = Secret::new(b"my secret".to_vec());

// Validate input with the `ensure!` macro
ensure!(secret.len() >= 16, "secret too short");
```

## API Reference

### Enums

#### `Algo`

```rust
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}
```

Supported HMAC algorithms for OTP generation.

- **`Sha1`** – SHA‑1 (legacy, not recommended for new applications)
- **`Sha256`** – SHA‑256 (default)
- **`Sha512`** – SHA‑512

The default algorithm is `Algo::Sha256`.

---

### Types

#### `Recipient`

An age‑compatible public key string.

```rust
pub struct Recipient(String);

impl Recipient {
    pub fn new(s: impl Into<String>) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
```

- **Validation**: Must start with `"age1"`, length > 4, and contain only alphanumeric characters, `-`, or `_`.
- **Errors**: `AuthError::InvalidInput`

```rust
let rec = Recipient::new("age1abc123")?;
assert_eq!(rec.as_str(), "age1abc123");
```

#### `Identity`

An age‑compatible secret key string.

```rust
pub struct Identity(String);

impl Identity {
    pub fn new(s: impl Into<String>) -> Result<Self>;
    pub fn as_str(&self) -> &str;
}
```

- **Validation**: Must start with `"AGE-SECRET-KEY-"` and length > 20.
- **Errors**: `AuthError::InvalidInput`

#### `Secret`

A byte vector containing sensitive data. **Zeroized on drop**.

```rust
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(data: Vec<u8>) -> Self;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn as_bytes(&self) -> &[u8];
}
```

- Implements `From<Vec<u8>>`.
- Derive `Clone`, `Debug` output is suppressed.

#### `Token`

An OTP token value (HOTP / TOTP result).

```rust
pub struct Token(u64);

impl Token {
    pub fn new(value: u64, digits: u32) -> Result<Self>;
    pub fn value(&self) -> u64;
    pub fn format(&self, digits: u32) -> String;
}
```

- **Validation**: `digits` must be 1‑10, and `value < 10^digits`.
- **`format`** returns the token zero‑padded to the given number of digits.

```rust
let token = Token::new(123456, 6)?;
assert_eq!(token.format(6), "123456");
```

#### `Base32String`

A validated Base32‑encoded string (RFC 4648, no padding).

```rust
pub struct Base32String(String);

impl Base32String {
    pub fn new(s: impl Into<String>) -> Result<Self>;
    pub fn as_str(&self) -> &str;
    pub fn to_secret(&self) -> Result<Secret>;
}
```

- **`new`** checks that the string can be decoded with the `Rfc4648 { padding: false }` alphabet.
- **`to_secret`** returns the decoded bytes wrapped in a `Secret`.

#### `TimeStep`

TOTP time step in seconds.

```rust
pub struct TimeStep(u64);

impl TimeStep {
    pub fn new(step: u64) -> Result<Self>;
    pub fn value(&self) -> u64;
}
```

- **Validation**: `step > 0`.
- **Default**: 30 seconds.

#### `Digits`

Number of digits for OTP tokens.

```rust
pub struct Digits(u32);

impl Digits {
    pub fn new(n: u32) -> Result<Self>;
    pub fn value(&self) -> u32;
}
```

- **Validation**: 4 ≤ `n` ≤ 10.
- **Default**: 6 digits.

#### `Counter`

An HOTP counter (64‑bit unsigned).

```rust
pub struct Counter(u64);

impl Counter {
    pub fn new(c: u64) -> Self;
    pub fn value(&self) -> u64;
    pub fn increment(&mut self);
}
```

#### `EncryptedPayload`

Wrapper around ciphertext bytes. **Zeroized on drop**.

```rust
pub struct EncryptedPayload(Zeroizing<Vec<u8>>);

impl EncryptedPayload {
    pub fn new(data: Vec<u8>) -> Self;
    pub fn as_bytes(&self) -> &[u8];
}
```

- Derive `Clone`, `PartialEq`, `Eq`. Debug output is hidden.

---

### Traits

#### `CryptoBackend`

```rust
pub trait CryptoBackend {
    fn encrypt(&self, recipient: &Recipient, plaintext: &Secret)
        -> Result<EncryptedPayload>;
    fn decrypt(&self, identity: &Identity, ciphertext: &EncryptedPayload)
        -> Result<Secret>;
}
```

Implemented by `libage_crypto::AgeCrypto`.

#### `OtpGenerator`

```rust
pub trait OtpGenerator {
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo)
        -> Result<Token>;
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo)
        -> Result<Token>;
    fn totp_now_from_base32(secret_base32: &Base32String)
        -> Result<String>;
}
```

Implemented by `libage_otp::AgeOtp`.

- `totp_now_from_base32` is a convenience method that decodes the Base32 secret, applies default time step and digits, and returns a formatted string.

#### `Authenticator`

```rust
pub trait Authenticator: CryptoBackend + OtpGenerator {
    fn provision(&self, public_key: &Recipient, secret: &Secret)
        -> Result<EncryptedPayload> { … }
    fn load_encrypted_secret(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<Secret>;
    fn generate_totp_from_encrypted(
        &self,
        identity_reader: &mut dyn Read,
        encrypted: &EncryptedPayload,
    ) -> Result<String> { … }
}
```

Implemented by `libage_authenticator::AgeAuthenticator`.

- **`provision`** (default) – encrypts a secret with a public key.
- **`load_encrypted_secret`** – reads an identity from a `Read` stream, decrypts the payload, and returns the secret.
- **`generate_totp_from_encrypted`** (default) – decrypts the secret, interprets it as a UTF‑8 Base32 string, and returns the current TOTP code.

#### `Validate`

```rust
pub trait Validate {
    fn validate(&self) -> Result<()>;
}
```

Optional trait that can be implemented by types that need custom validation beyond what the constructor provides.

---

### Error Handling

#### `AuthError`

```rust
pub enum AuthError {
    Crypto(String),      // cryptography-related errors
    Otp(String),         // OTP generation errors
    InvalidInput(String),// invalid input from the user
    Io(std::io::Error),  // I/O errors (transparent)
    Other(Box<dyn Error + Send + Sync>), // any other error
}
```

Implements `std::error::Error` and `Display`.  
Conversions:

- `From<io::Error>` → `AuthError::Io`
- `From<Box<dyn Error + Send + Sync>>` → `AuthError::Other`

#### `Result`

```rust
pub type Result<T> = std::result::Result<T, AuthError>;
```

---

### Macros

#### `ensure!`

```rust
ensure!(condition, "error message");
ensure!(condition, error_expression);
```

If `condition` is false, returns `Err(AuthError::InvalidInput(...))`.

#### `bail!`

```rust
bail!("error message");
bail!(error_expression);
```

Immediately returns `Err(AuthError::InvalidInput(...))` (or any `AuthError` variant if given).

---

### Constants

```rust
pub const DEFAULT_TIME_STEP: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_ALGO: Algo = Algo::Sha256;
```

## Safety & Security

- All sensitive byte containers (`Secret`, `EncryptedPayload`) use the `zeroize` crate and are cleared on drop.
- Public types guard invariants at construction, preventing invalid states.
- The `Identity` and `Recipient` strings are not automatically zeroized – the caller must ensure appropriate handling.

## License

Licensed under the MIT License. See `LICENSE` for details.

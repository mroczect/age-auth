# libage_otp

OTP (TOTP/HOTP) generator, independent of age, for the age-auth library.  
This crate provides a pure Rust implementation of the `OtpGenerator` trait from `libage_auth_handler`.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [`AgeOtp`](#ageotp)
    - [`OtpGenerator` trait implementation](#otpgenerator-trait-implementation)
  - [Advanced – `algorithms` module](#advanced--algorithms-module)
    - [`compute_hotp_at`](#compute_hotp_at)
    - [`compute_totp_at`](#compute_totp_at)
- [Testing & Benchmark](#testing--benchmark)
- [Security](#security)
- [License](#license)

## Features

- **Full `OtpGenerator` implementation** – generate TOTP and HOTP tokens using SHA‑1, SHA‑256, or SHA‑512.
- **Validated parameters** – all inputs are accepted through the strongly typed wrappers from `libage_auth_handler` (`Secret`, `Digits`, `TimeStep`, `Counter`, `Algo`, `Base32String`).
- **Dynamic truncation** – conforms to RFC 4226 section 5.3.
- **Zero‑panic time retrieval** – system clock errors are returned as `AuthError::Otp`, never panics.
- **Benchmarks** – criterion benchmarks included for every algorithm and digit length.
- **No unsafe code**, no unwraps in production code.

## Installation

```toml
[dependencies]
libage_otp = { path = "../libage_otp" }
```

```toml
[dependencies]
libage_otp = "0.1"
```

## Quick Start

```rust
use libage_otp::AgeOtp;
use libage_auth_handler::traits::OtpGenerator;
use libage_auth_handler::types::{Secret, Digits, Counter, TimeStep, Base32String, Algo};

// Create a secret (must be kept confidential)
let secret = Secret::new(b"12345678901234567890".to_vec());

// HOTP – counter-based
let counter = Counter::new(0);
let token = AgeOtp::hotp(&secret, counter, Digits::new(6)?, Algo::Sha1)?;
println!("HOTP: {}", token.format(6));

// TOTP – time-based (uses current system time)
let time_step = TimeStep::new(30)?;
let token = AgeOtp::totp(&secret, time_step, Digits::new(8)?, Algo::Sha256)?;
println!("TOTP: {}", token.format(8));

// Convenience: decode a base32 secret and get the current TOTP code
let base32 = Base32String::new("JBSWY3DPEHPK3PXP")?;
let code = AgeOtp::totp_now_from_base32(&base32)?;
println!("Current TOTP (6 digits, SHA‑256): {}", code);
```

## API Reference

### `AgeOtp`

```rust
pub struct AgeOtp;
```

Zero‑sized struct that implements `OtpGenerator`. All methods are associated functions (no `self` parameter), so they are called directly via `AgeOtp::`.

#### `OtpGenerator` trait implementation

```rust
impl OtpGenerator for AgeOtp {
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token>;
    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token>;
    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String>;
}
```

##### `totp`

```rust
AgeOtp::totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token>
```

Generates a time‑based one‑time password (TOTP) according to RFC 6238.

- **`secret`** – the shared secret.
- **`time_step`** – time step in seconds (e.g., 30).
- **`digits`** – number of digits for the token (4‑10).
- **`algo`** – HMAC algorithm (`Sha1`, `Sha256`, or `Sha512`).

Returns a `Token` that can be formatted with `token.format(digits.value())`.  
Uses `SystemTime::now()` internally – if the system clock is before the Unix epoch, an error is returned.

##### `hotp`

```rust
AgeOtp::hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token>
```

Generates a counter‑based one‑time password (HOTP) according to RFC 4226.

- **`secret`** – the shared secret.
- **`counter`** – 64‑bit counter value.
- **`digits`** – number of digits for the token (4‑10).
- **`algo`** – HMAC algorithm.

Returns a `Token`.

##### `totp_now_from_base32`

```rust
AgeOtp::totp_now_from_base32(secret_base32: &Base32String) -> Result<String>
```

Convenience method that:

1. Decodes the base32 `secret_base32` into a `Secret`.
2. Uses default `TimeStep` (30s), `Digits` (6), and `Algo` (SHA‑256).
3. Calls `totp` and returns the formatted string.

### Advanced – `algorithms` module

The module `libage_otp::algorithms` exposes the underlying functions for users who need direct control over timestamps or counters.

```rust
pub fn compute_hotp_at(
    secret: &Secret,
    counter: u64,
    digits: Digits,
    algo: Algo,
) -> Result<Token>;

pub fn compute_totp_at(
    secret: &Secret,
    timestamp: u64,
    time_step: TimeStep,
    digits: Digits,
    algo: Algo,
) -> Result<Token>;
```

#### `compute_hotp_at`

Direct HOTP calculation with a raw `counter` value (no `Counter` wrapper).  
Useful when you already have a numeric counter.

#### `compute_totp_at`

Direct TOTP calculation with a raw Unix `timestamp` (seconds since epoch).  
Allows deterministic testing by providing a fixed timestamp.

Example:

```rust
use libage_otp::algorithms::compute_totp_at;
use libage_auth_handler::types::{Secret, TimeStep, Digits};
use libage_auth_handler::Algo;

let secret = Secret::new(b"12345678901234567890".to_vec());
let token = compute_totp_at(&secret, 1700000000, TimeStep::new(30).unwrap(), Digits::new(8).unwrap(), Algo::Sha256)?;
println!("TOTP at timestamp 1.7e9: {}", token.format(8));
```

## Testing & Benchmark

### Unit tests

The crate includes extensive unit tests that verify against RFC 4226 test vectors (HOTP) and custom deterministic TOTP vectors.

```bash
cargo test
```

### Benchmarks

Benchmarks are provided for HOTP, TOTP, and the public API overhead.

```bash
cargo bench
```

Results are written to `target/criterion/` and include HTML reports.

## Security

- **No unwrap/panic** – `current_unix_time` returns an error instead of panicking on clock issues.
- **HMAC buffers** are dropped immediately after truncation; the `Secret` is only accessed via `&[u8]`.
- **Input validation** – all parameters are validated by `libage_auth_handler` types; `Digits`, `TimeStep`, `Base32String` cannot represent invalid values.
- **Algorithm flexibility** – the default algorithm is SHA‑256, not SHA‑1.

## License

MIT – see `LICENSE` for details.

use hmac::KeyInit;
use hmac::{Hmac, Mac};
use libage_auth_handler::Algo;
use libage_auth_handler::errors::{AuthError, Result};
#[cfg(test)]
use libage_auth_handler::types::Base32String;
use libage_auth_handler::types::{Digits, Secret, TimeStep, Token};

fn dynamic_truncate(hmac: &[u8], digits: u32) -> u64 {
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    let b1 = (hmac[offset] & 0x7f) as u64;
    let b2 = hmac[offset + 1] as u64;
    let b3 = hmac[offset + 2] as u64;
    let b4 = hmac[offset + 3] as u64;
    let binary = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    binary % 10u64.pow(digits)
}

pub fn compute_hotp_at(secret: &Secret, counter: u64, digits: Digits, algo: Algo) -> Result<Token> {
    let counter_bytes = counter.to_be_bytes();
    let value = match algo {
        Algo::Sha1 => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
        Algo::Sha256 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
        Algo::Sha512 => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(secret.as_bytes())
                .map_err(|e| AuthError::Otp(format!("Invalid key: {}", e)))?;
            mac.update(&counter_bytes);
            let result = mac.finalize().into_bytes();
            dynamic_truncate(&result, digits.value())
        }
    };
    Token::new(value, digits.value()).map_err(|e| AuthError::Otp(e.to_string()))
}

pub fn compute_totp_at(
    secret: &Secret,
    timestamp: u64,
    time_step: TimeStep,
    digits: Digits,
    algo: Algo,
) -> Result<Token> {
    let steps = timestamp / time_step.value();
    compute_hotp_at(secret, steps, digits, algo)
}

pub(crate) fn current_unix_time() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AuthError::Otp("System clock before UNIX epoch".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_secret() -> Secret {
        Base32String::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap()
            .to_secret()
            .unwrap()
    }

    #[test]
    fn hotp_rfc4226_vector_0() {
        let t = compute_hotp_at(&rfc_secret(), 0, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 755224);
    }
    #[test]
    fn hotp_rfc4226_vector_1() {
        let t = compute_hotp_at(&rfc_secret(), 1, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 287082);
    }
    #[test]
    fn hotp_rfc4226_vector_2() {
        let t = compute_hotp_at(&rfc_secret(), 2, Digits::new(6).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 359152);
    }
    #[test]
    fn hotp_8digit_vector_0() {
        let t = compute_hotp_at(&rfc_secret(), 0, Digits::new(8).unwrap(), Algo::Sha1).unwrap();
        assert_eq!(t.value(), 84755224);
    }

    #[test]
    fn totp_sha1_vectors() {
        let s = Secret::new(b"12345678901234567890".to_vec());
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha1).unwrap().value(),
            94287082
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha1)
                .unwrap()
                .value(),
            7081804
        );
    }

    #[test]
    fn totp_sha256_vectors() {
        let s = Secret::new(b"12345678901234567890123456789012".to_vec());
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha256)
                .unwrap()
                .value(),
            46119246
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha256)
                .unwrap()
                .value(),
            68084774
        );
    }

    #[test]
    fn totp_sha512_vectors() {
        let s = Secret::new(
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
        );
        let ts = TimeStep::new(30).unwrap();
        let d8 = Digits::new(8).unwrap();
        assert_eq!(
            compute_totp_at(&s, 59, ts, d8, Algo::Sha512)
                .unwrap()
                .value(),
            90693936
        );
        assert_eq!(
            compute_totp_at(&s, 1111111109, ts, d8, Algo::Sha512)
                .unwrap()
                .value(),
            25091201
        );
    }

    #[test]
    fn edge_case_short_secret_ok() {
        let secret = Secret::new(b"1234567890".to_vec());
        assert!(compute_hotp_at(&secret, 0, Digits::new(6).unwrap(), Algo::Sha1).is_ok());
    }
}

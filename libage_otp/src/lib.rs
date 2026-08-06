pub mod algorithms;

use libage_auth_handler::Algo;
use libage_auth_handler::errors::Result;
use libage_auth_handler::traits::OtpGenerator;
use libage_auth_handler::types::{Base32String, Counter, Digits, Secret, TimeStep, Token};

pub struct AgeOtp;

impl OtpGenerator for AgeOtp {
    fn totp(secret: &Secret, time_step: TimeStep, digits: Digits, algo: Algo) -> Result<Token> {
        let now = algorithms::current_unix_time()?;
        algorithms::compute_totp_at(secret, now, time_step, digits, algo)
    }

    fn hotp(secret: &Secret, counter: Counter, digits: Digits, algo: Algo) -> Result<Token> {
        algorithms::compute_hotp_at(secret, counter.value(), digits, algo)
    }

    fn totp_now_from_base32(secret_base32: &Base32String) -> Result<String> {
        let secret = secret_base32.to_secret()?;
        let time_step = TimeStep::default();
        let digits = Digits::default();
        let token = Self::totp(&secret, time_step, digits, Algo::DEFAULT)?;
        Ok(token.format(digits.value()))
    }
}

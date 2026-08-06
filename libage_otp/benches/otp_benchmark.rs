use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libage_auth_handler::Algo;
use libage_auth_handler::types::{Base32String, Counter, Digits, Secret, TimeStep};

use libage_auth_handler::traits::OtpGenerator;
use libage_otp::AgeOtp;

use libage_otp::algorithms::{compute_hotp_at, compute_totp_at};

fn bench_hotp(c: &mut Criterion) {
    let secret = Secret::new(b"12345678901234567890".to_vec());
    let counter = 123456u64;
    let digits6 = Digits::new(6).unwrap();
    let digits8 = Digits::new(8).unwrap();

    let mut group = c.benchmark_group("HOTP");
    group.bench_function("sha1_6digit", |b| {
        b.iter(|| {
            compute_hotp_at(
                black_box(&secret),
                black_box(counter),
                black_box(digits6),
                black_box(Algo::Sha1),
            )
        })
    });
    group.bench_function("sha256_6digit", |b| {
        b.iter(|| {
            compute_hotp_at(
                black_box(&secret),
                black_box(counter),
                black_box(digits6),
                black_box(Algo::Sha256),
            )
        })
    });
    group.bench_function("sha512_6digit", |b| {
        b.iter(|| {
            compute_hotp_at(
                black_box(&secret),
                black_box(counter),
                black_box(digits6),
                black_box(Algo::Sha512),
            )
        })
    });
    group.bench_function("sha1_8digit", |b| {
        b.iter(|| {
            compute_hotp_at(
                black_box(&secret),
                black_box(counter),
                black_box(digits8),
                black_box(Algo::Sha1),
            )
        })
    });
    group.finish();
}

fn bench_totp(c: &mut Criterion) {
    let secret = Secret::new(b"12345678901234567890".to_vec());
    let time_step = TimeStep::new(30).unwrap();
    let digits8 = Digits::new(8).unwrap();
    let timestamp = 1700000000u64;

    let mut group = c.benchmark_group("TOTP (fixed timestamp)");
    group.bench_function("sha1_8digit", |b| {
        b.iter(|| {
            compute_totp_at(
                black_box(&secret),
                black_box(timestamp),
                black_box(time_step),
                black_box(digits8),
                black_box(Algo::Sha1),
            )
        })
    });
    group.bench_function("sha256_8digit", |b| {
        b.iter(|| {
            compute_totp_at(
                black_box(&secret),
                black_box(timestamp),
                black_box(time_step),
                black_box(digits8),
                black_box(Algo::Sha256),
            )
        })
    });
    group.bench_function("sha512_8digit", |b| {
        b.iter(|| {
            compute_totp_at(
                black_box(&secret),
                black_box(timestamp),
                black_box(time_step),
                black_box(digits8),
                black_box(Algo::Sha512),
            )
        })
    });
    group.finish();
}

fn bench_api(c: &mut Criterion) {
    let secret = Secret::new(b"12345678901234567890".to_vec());
    let counter = Counter::new(42);
    let digits6 = Digits::new(6).unwrap();
    let algo = Algo::Sha1;

    c.bench_function("AgeOtp::hotp (API)", |b| {
        b.iter(|| {
            AgeOtp::hotp(
                black_box(&secret),
                black_box(counter),
                black_box(digits6),
                black_box(algo),
            )
        })
    });

    let base32_str = Base32String::new("JBSWY3DPEHPK3PXP").unwrap();
    c.bench_function("AgeOtp::totp_now_from_base32 (API)", |b| {
        b.iter(|| AgeOtp::totp_now_from_base32(black_box(&base32_str)))
    });
}

criterion_group!(benches, bench_hotp, bench_totp, bench_api);
criterion_main!(benches);

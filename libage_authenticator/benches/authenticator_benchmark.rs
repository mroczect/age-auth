use criterion::{Criterion, black_box, criterion_group, criterion_main};
use libage_auth_handler::traits::Authenticator;
use libage_auth_handler::types::Secret;
use libage_authenticator::AgeAuthenticator;
use libage_crypto::generate_keypair;
use std::io::Cursor;

fn bench_provision(c: &mut Criterion) {
    let auth = AgeAuthenticator::new();
    let (recipient, _) = generate_keypair().unwrap();
    let secret = Secret::new(b"benchmark-secret-123456".to_vec());
    c.bench_function("provision (encrypt)", |b| {
        b.iter(|| auth.provision(black_box(&recipient), black_box(&secret)))
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let auth = AgeAuthenticator::new();
    let (recipient, identity) = generate_keypair().unwrap();
    let secret = Secret::new(b"benchmark-secret-123456".to_vec());
    let encrypted = auth.provision(&recipient, &secret).unwrap();
    c.bench_function("load_encrypted_secret (decrypt)", |b| {
        b.iter(|| {
            let mut reader = Cursor::new(identity.as_str().as_bytes());
            auth.load_encrypted_secret(&mut reader, black_box(&encrypted))
        })
    });
}

fn bench_generate_totp(c: &mut Criterion) {
    let auth = AgeAuthenticator::new();
    let (recipient, identity) = generate_keypair().unwrap();
    let base32_str = "JBSWY3DPEHPK3PXP";
    let secret = Secret::new(base32_str.as_bytes().to_vec());
    let encrypted = auth.provision(&recipient, &secret).unwrap();
    c.bench_function("generate_totp_from_encrypted (full flow)", |b| {
        b.iter(|| {
            let mut reader = Cursor::new(identity.as_str().as_bytes());
            auth.generate_totp_from_encrypted(&mut reader, black_box(&encrypted))
        })
    });
}

criterion_group!(benches, bench_provision, bench_decrypt, bench_generate_totp);
criterion_main!(benches);

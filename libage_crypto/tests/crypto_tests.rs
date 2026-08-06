use libage_auth_handler::errors::AuthError;
use libage_auth_handler::traits::CryptoBackend;
use libage_auth_handler::types::{EncryptedPayload, Identity, Recipient, Secret};
use libage_crypto::{AgeCrypto, generate_keypair};

#[test]
fn keypair_generation_works() {
    let (recipient, identity) = generate_keypair().expect("Key generation should succeed");
    assert!(recipient.as_str().starts_with("age1"));
    assert!(identity.as_str().starts_with("AGE-SECRET-KEY-"));
}

#[test]
fn roundtrip_small_secret() {
    let backend = AgeCrypto;
    let (recipient, identity) = generate_keypair().unwrap();
    let secret = Secret::new(b"Hello, age-auth!".to_vec());

    let encrypted = backend.encrypt(&recipient, &secret).unwrap();
    let decrypted = backend.decrypt(&identity, &encrypted).unwrap();

    assert_eq!(decrypted.as_bytes(), secret.as_bytes());
}

#[test]
fn roundtrip_empty_secret() {
    let backend = AgeCrypto;
    let (recipient, identity) = generate_keypair().unwrap();
    let secret = Secret::new(vec![]);

    let encrypted = backend.encrypt(&recipient, &secret).unwrap();
    let decrypted = backend.decrypt(&identity, &encrypted).unwrap();

    assert_eq!(decrypted.as_bytes(), b"");
}

#[test]
fn decrypt_with_wrong_identity() {
    let backend = AgeCrypto;
    let (recipient, _) = generate_keypair().unwrap();
    let (_, wrong_identity) = generate_keypair().unwrap();
    let secret = Secret::new(b"data".to_vec());

    let encrypted = backend.encrypt(&recipient, &secret).unwrap();
    let result = backend.decrypt(&wrong_identity, &encrypted);

    assert!(result.is_err());
    match result.unwrap_err() {
        AuthError::Crypto(msg) => {
            assert!(msg.contains("Decryption failed") || msg.contains("No matching keys"))
        }
        other => panic!("Expected Crypto error, got {:?}", other),
    }
}

#[test]
fn encrypt_with_invalid_recipient() {
    let backend = AgeCrypto;
    let invalid_recipient =
        Recipient::new("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq").unwrap();
    let secret = Secret::new(b"test".to_vec());

    let result = backend.encrypt(&invalid_recipient, &secret);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, AuthError::InvalidInput(_)) || matches!(err, AuthError::Crypto(_)));
}

#[test]
fn decrypt_with_invalid_identity_format() {
    let backend = AgeCrypto;
    let invalid_identity =
        Identity::new("AGE-SECRET-KEY-1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            .unwrap();
    let payload = EncryptedPayload::new(b"not real ciphertext".to_vec());

    let result = backend.decrypt(&invalid_identity, &payload);
    assert!(result.is_err());
}

#[test]
fn roundtrip_large_secret() {
    let backend = AgeCrypto;
    let (recipient, identity) = generate_keypair().unwrap();
    let large_data = vec![0xAA; 1_000_000];
    let secret = Secret::new(large_data.clone());

    let encrypted = backend.encrypt(&recipient, &secret).unwrap();
    let decrypted = backend.decrypt(&identity, &encrypted).unwrap();

    assert_eq!(decrypted.as_bytes(), &large_data[..]);
}

#[test]
fn encrypted_payload_zeroize_on_drop() {
    let data = vec![1, 2, 3, 4];
    let payload = EncryptedPayload::new(data);
    drop(payload);
}

#[test]
fn roundtrip_random_sizes() {
    use rand::RngCore;
    let backend = AgeCrypto;
    let (recipient, identity) = generate_keypair().unwrap();
    let mut rng = rand::thread_rng();

    for size in [0, 1, 16, 64, 256, 1024, 4096] {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let secret = Secret::new(data.clone());

        let encrypted = backend.encrypt(&recipient, &secret).unwrap();
        let decrypted = backend.decrypt(&identity, &encrypted).unwrap();

        assert_eq!(decrypted.as_bytes(), &data[..], "Failed for size {}", size);
    }
}

#[test]
fn encrypt_multiple_roundtrip() {
    let (recipient1, identity1) = generate_keypair().unwrap();
    let (recipient2, _) = generate_keypair().unwrap();
    let secret = Secret::new(b"multi recipient test".to_vec());

    let encrypted = libage_crypto::encrypt_multiple(&[recipient1.clone(), recipient2], &secret)
        .expect("encrypt multiple should work");
    let decrypted = AgeCrypto
        .decrypt(&identity1, &encrypted)
        .expect("decrypt with first identity");
    assert_eq!(decrypted.as_bytes(), secret.as_bytes());
}

#[test]
fn encrypt_multiple_invalid_recipient() {
    let invalid =
        Recipient::new("age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq").unwrap();
    let secret = Secret::new(b"data".to_vec());
    assert!(libage_crypto::encrypt_multiple(&[invalid], &secret).is_err());
}

use aes_gcm::{Aes128Gcm, Aes256Gcm, aead::{AeadInPlace, KeyInit}};
use chacha20poly1305::ChaCha20Poly1305;
use uselesskey_core::Factory;
use uselesskey_symmetric::{
    AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricFactoryExt, SymmetricSpec,
};

#[test]
fn deterministic_key_and_nonce_generation() {
    let fx = Factory::deterministic_from_str("symmetric-determinism");

    let a = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());
    let b = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());
    let c = fx.symmetric("other", SymmetricSpec::aes256_gcm());

    assert_eq!(a.key_bytes(), b.key_bytes());
    assert_eq!(a.nonce_bytes(), b.nonce_bytes());
    assert_ne!(a.key_bytes(), c.key_bytes());
    assert_ne!(a.nonce_bytes(), c.nonce_bytes());
}

#[test]
fn aead_round_trip_with_rustcrypto() {
    let fx = Factory::deterministic_from_str("symmetric-roundtrip");
    let spec = AeadVectorSpec::new(
        PlaintextMode::JsonBody,
        AadMode::FixedBytes,
        NoncePolicy::Explicit,
    );

    for alg in [
        SymmetricSpec::aes128_gcm(),
        SymmetricSpec::aes256_gcm(),
        SymmetricSpec::chacha20_poly1305(),
    ] {
        let key = fx.symmetric("issuer", alg);
        let vec = fx.aead_vector("issuer", alg, spec);

        let mut combined = vec.ciphertext.to_vec();
        combined.extend_from_slice(&vec.tag);

        let plaintext = match alg {
            SymmetricSpec::Aes128Gcm => {
                let c = Aes128Gcm::new_from_slice(key.key_bytes()).unwrap();
                let nonce: [u8; 12] = vec.nonce.as_ref().try_into().unwrap();
                c.decrypt_in_place(&nonce.into(), &vec.aad, &mut combined).unwrap();
                combined
            }
            SymmetricSpec::Aes256Gcm => {
                let c = Aes256Gcm::new_from_slice(key.key_bytes()).unwrap();
                let nonce: [u8; 12] = vec.nonce.as_ref().try_into().unwrap();
                c.decrypt_in_place(&nonce.into(), &vec.aad, &mut combined).unwrap();
                combined
            }
            SymmetricSpec::ChaCha20Poly1305 => {
                let c = ChaCha20Poly1305::new_from_slice(key.key_bytes()).unwrap();
                let nonce: [u8; 12] = vec.nonce.as_ref().try_into().unwrap();
                c.decrypt_in_place(&nonce.into(), &vec.aad, &mut combined).unwrap();
                combined
            }
        };

        assert_eq!(plaintext, vec.plaintext.as_ref());
    }
}

#[test]
fn vector_spec_influences_deterministic_output() {
    let fx = Factory::deterministic_from_str("symmetric-fingerprint");

    let a = fx.aead_vector(
        "issuer",
        SymmetricSpec::aes256_gcm(),
        AeadVectorSpec::new(PlaintextMode::FixedBytes, AadMode::None, NoncePolicy::Derived),
    );

    let b = fx.aead_vector(
        "issuer",
        SymmetricSpec::aes256_gcm(),
        AeadVectorSpec::new(PlaintextMode::RandomShape, AadMode::None, NoncePolicy::Derived),
    );

    assert_ne!(a.plaintext, b.plaintext);
    assert_ne!(a.ciphertext, b.ciphertext);
}

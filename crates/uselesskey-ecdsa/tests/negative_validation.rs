//! Negative fixture validation tests for ECDSA keys.
//!
//! Ensures ALL CorruptPem variants produce unparsable output for both
//! P-256 and P-384, corrupt DER fails parsing, mismatched keys fail
//! signature verification, and negative fixtures are deterministic.

#[allow(dead_code)]
mod testutil;

use p256::ecdsa::{
    Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
    signature::Signer as _, signature::Verifier as _,
};
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

// =========================================================================
// All CorruptPem variants fail PEM parsing for P-256
// =========================================================================

#[test]
fn all_corrupt_pem_variants_fail_parsing_es256() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-pem-256").unwrap());
    let kp = fx.ecdsa("neg-pem-256", EcdsaSpec::es256());
    let original = kp.private_key_pkcs8_pem();

    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 20 },
        CorruptPem::ExtraBlankLine,
    ];

    for variant in &variants {
        let bad = kp.private_key_pkcs8_pem_corrupt(*variant);
        assert_ne!(bad, original, "CorruptPem::{variant:?} should differ");
        use p256::pkcs8::DecodePrivateKey as _;
        assert!(
            p256::SecretKey::from_pkcs8_pem(&bad).is_err(),
            "CorruptPem::{variant:?} should fail P-256 PEM parsing"
        );
    }
}

// =========================================================================
// All CorruptPem variants fail PEM parsing for P-384
// =========================================================================

#[test]
fn all_corrupt_pem_variants_fail_parsing_es384() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-pem-384").unwrap());
    let kp = fx.ecdsa("neg-pem-384", EcdsaSpec::es384());
    let original = kp.private_key_pkcs8_pem();

    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 20 },
        CorruptPem::ExtraBlankLine,
    ];

    for variant in &variants {
        let bad = kp.private_key_pkcs8_pem_corrupt(*variant);
        assert_ne!(bad, original, "CorruptPem::{variant:?} should differ");
        use p384::pkcs8::DecodePrivateKey as _;
        assert!(
            p384::SecretKey::from_pkcs8_pem(&bad).is_err(),
            "CorruptPem::{variant:?} should fail P-384 PEM parsing"
        );
    }
}

// =========================================================================
// Corrupt DER variants fail parsing for both curves
// =========================================================================

#[test]
fn truncated_der_fails_parsing_es256() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-der-256").unwrap());
    let kp = fx.ecdsa("neg-der-trunc-256", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(8);
    use p256::pkcs8::DecodePrivateKey as _;
    assert!(
        p256::SecretKey::from_pkcs8_der(&truncated).is_err(),
        "Truncated DER should fail P-256 parsing"
    );
}

#[test]
fn truncated_der_fails_parsing_es384() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-der-384").unwrap());
    let kp = fx.ecdsa("neg-der-trunc-384", EcdsaSpec::es384());
    let truncated = kp.private_key_pkcs8_der_truncated(8);
    use p384::pkcs8::DecodePrivateKey as _;
    assert!(
        p384::SecretKey::from_pkcs8_der(&truncated).is_err(),
        "Truncated DER should fail P-384 parsing"
    );
}

#[test]
fn corrupt_der_deterministic_fails_parsing_es256() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-cder-256").unwrap());
    let kp = fx.ecdsa("neg-cder-256", EcdsaSpec::es256());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ecdsa-v1");
    use p256::pkcs8::DecodePrivateKey as _;
    assert!(
        p256::SecretKey::from_pkcs8_der(&corrupted).is_err(),
        "Corrupted DER should fail P-256 parsing"
    );
}

#[test]
fn corrupt_der_deterministic_fails_parsing_es384() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-cder-384").unwrap());
    let kp = fx.ecdsa("neg-cder-384", EcdsaSpec::es384());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ecdsa-v1");
    use p384::pkcs8::DecodePrivateKey as _;
    assert!(
        p384::SecretKey::from_pkcs8_der(&corrupted).is_err(),
        "Corrupted DER should fail P-384 parsing"
    );
}

// =========================================================================
// Mismatched keys fail signature verification (P-256)
// =========================================================================

#[test]
fn mismatched_public_key_rejects_signature_es256() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-neg-mm-256").unwrap());
    let kp = fx.ecdsa("neg-mm-sig-256", EcdsaSpec::es256());

    use p256::pkcs8::DecodePrivateKey as _;
    let secret = p256::SecretKey::from_pkcs8_der(kp.private_key_pkcs8_der()).unwrap();
    let signing_key = P256SigningKey::from(secret);
    let message = b"test message for ECDSA verification";
    let signature: Signature = signing_key.sign(message);

    // Correct key verifies
    use p256::pkcs8::DecodePublicKey as _;
    let good_pub = p256::PublicKey::from_public_key_der(kp.public_key_spki_der()).unwrap();
    let good_vk = P256VerifyingKey::from(good_pub);
    assert!(
        good_vk.verify(message, &signature).is_ok(),
        "Verification with correct key should succeed"
    );

    // Mismatched key fails
    let mm_der = kp.mismatched_public_key_spki_der();
    let mm_pub = p256::PublicKey::from_public_key_der(&mm_der).unwrap();
    let mm_vk = P256VerifyingKey::from(mm_pub);
    assert!(
        mm_vk.verify(message, &signature).is_err(),
        "Verification with mismatched key should fail"
    );
}

// =========================================================================
// Negative fixtures are deterministic
// =========================================================================

#[test]
fn corrupt_pem_deterministic_is_stable_es256() {
    let seed = Seed::from_env_value("ecdsa-det-neg-pem").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.ecdsa("det-neg-256", EcdsaSpec::es256());
    let kp2 = fx2.ecdsa("det-neg-256", EcdsaSpec::es256());

    for variant in ["corrupt:v1", "corrupt:v2", "corrupt:v3"] {
        assert_eq!(
            kp1.private_key_pkcs8_pem_corrupt_deterministic(variant),
            kp2.private_key_pkcs8_pem_corrupt_deterministic(variant),
            "Deterministic PEM corruption should be stable for {variant}"
        );
    }
}

#[test]
fn corrupt_der_deterministic_is_stable_es256() {
    let seed = Seed::from_env_value("ecdsa-det-neg-der").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.ecdsa("det-neg-der-256", EcdsaSpec::es256());
    let kp2 = fx2.ecdsa("det-neg-der-256", EcdsaSpec::es256());

    for variant in ["corrupt:v1", "corrupt:v2", "corrupt:v3"] {
        assert_eq!(
            kp1.private_key_pkcs8_der_corrupt_deterministic(variant),
            kp2.private_key_pkcs8_der_corrupt_deterministic(variant),
            "Deterministic DER corruption should be stable for {variant}"
        );
    }
}

#[test]
fn mismatch_key_is_deterministic_es256() {
    let seed = Seed::from_env_value("ecdsa-det-mm").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let mm1 = fx1
        .ecdsa("det-mm-256", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();
    let mm2 = fx2
        .ecdsa("det-mm-256", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();

    assert_eq!(mm1, mm2, "Mismatched key should be deterministic");
}

// =========================================================================
// Corrupt PEM variants are pairwise distinct
// =========================================================================

#[test]
fn corrupt_pem_variants_are_pairwise_distinct_es256() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-pairwise").unwrap());
    let kp = fx.ecdsa("neg-distinct-256", EcdsaSpec::es256());

    let outputs: Vec<String> = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 20 },
        CorruptPem::ExtraBlankLine,
    ]
    .iter()
    .map(|v| kp.private_key_pkcs8_pem_corrupt(*v))
    .collect();

    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            assert_ne!(outputs[i], outputs[j], "Variants {i} and {j} should differ");
        }
    }
}

//! Negative fixture validation tests for Ed25519 keys.
//!
//! Ensures ALL CorruptPem variants produce unparsable output,
//! corrupt DER fails parsing, mismatched keys fail signature
//! verification, and negative fixtures are deterministic.

mod testutil;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

// =========================================================================
// All CorruptPem variants fail PEM parsing
// =========================================================================

#[test]
fn all_corrupt_pem_variants_fail_parsing() {
    let fx = fx();
    let kp = fx.ed25519("neg-pem-all", Ed25519Spec::new());
    let original = kp.private_key_pkcs8_pem();

    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 15 },
        CorruptPem::ExtraBlankLine,
    ];

    for variant in &variants {
        let bad = kp.private_key_pkcs8_pem_corrupt(*variant);
        assert_ne!(bad, original, "CorruptPem::{variant:?} should differ");
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        assert!(
            SigningKey::from_pkcs8_pem(&bad).is_err(),
            "CorruptPem::{variant:?} should fail Ed25519 PEM parsing"
        );
    }
}

// =========================================================================
// Individual CorruptPem variants with specific assertions
// =========================================================================

#[test]
fn corrupt_pem_bad_header_contains_corrupted_marker() {
    let fx = fx();
    let kp = fx.ed25519("neg-hdr", Ed25519Spec::new());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(bad.contains("CORRUPTED"));
}

#[test]
fn corrupt_pem_bad_footer_contains_corrupted_marker() {
    let fx = fx();
    let kp = fx.ed25519("neg-ftr", Ed25519Spec::new());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(bad.contains("CORRUPTED"));
}

#[test]
fn corrupt_pem_bad_base64_contains_marker() {
    let fx = fx();
    let kp = fx.ed25519("neg-b64", Ed25519Spec::new());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_pem_truncate_is_shorter() {
    let fx = fx();
    let kp = fx.ed25519("neg-trunc-pem", Ed25519Spec::new());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_eq!(bad.len(), 10);
}

// =========================================================================
// Corrupt DER variants fail parsing
// =========================================================================

#[test]
fn truncated_der_fails_parsing() {
    let fx = fx();
    let kp = fx.ed25519("neg-der-trunc", Ed25519Spec::new());
    let truncated = kp.private_key_pkcs8_der_truncated(8);
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    assert!(
        SigningKey::from_pkcs8_der(&truncated).is_err(),
        "Truncated DER should fail Ed25519 parsing"
    );
}

#[test]
fn corrupt_der_deterministic_fails_parsing() {
    let fx = fx();
    let kp = fx.ed25519("neg-cder", Ed25519Spec::new());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:ed25519-v1");
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    assert!(
        SigningKey::from_pkcs8_der(&corrupted).is_err(),
        "Corrupted DER should fail Ed25519 parsing"
    );
}

#[test]
fn multiple_corrupt_der_variants_all_differ_from_original() {
    let fx = fx();
    let kp = fx.ed25519("neg-cder-multi", Ed25519Spec::new());
    let original = kp.private_key_pkcs8_der();
    for variant in ["corrupt:a", "corrupt:b", "corrupt:c", "corrupt:d"] {
        let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic(variant);
        assert_ne!(
            corrupted.as_slice(),
            original,
            "Variant {variant} should differ from original"
        );
    }
}

// =========================================================================
// Mismatched keys fail signature verification
// =========================================================================

#[test]
fn mismatched_public_key_rejects_signature() {
    let fx = fx();
    let kp = fx.ed25519("neg-mm-sig", Ed25519Spec::new());

    use ed25519_dalek::pkcs8::DecodePrivateKey as _;
    let signing_key = SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der()).unwrap();
    let message = b"test message for Ed25519 verification";
    let signature = signing_key.sign(message);

    // Correct key verifies
    let good_vk: VerifyingKey = signing_key.verifying_key();
    assert!(
        good_vk.verify(message, &signature).is_ok(),
        "Verification with correct key should succeed"
    );

    // Mismatched key fails
    let mm_der = kp.mismatched_public_key_spki_der();
    use ed25519_dalek::pkcs8::DecodePublicKey as _;
    let mm_vk = VerifyingKey::from_public_key_der(&mm_der).unwrap();
    assert!(
        mm_vk.verify(message, &signature).is_err(),
        "Verification with mismatched key should fail"
    );
}

// =========================================================================
// Negative fixtures are deterministic
// =========================================================================

#[test]
fn corrupt_pem_deterministic_is_stable() {
    let seed = Seed::from_env_value("ed25519-neg-det-pem").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.ed25519("det-neg", Ed25519Spec::new());
    let kp2 = fx2.ed25519("det-neg", Ed25519Spec::new());

    for variant in ["corrupt:v1", "corrupt:v2", "corrupt:v3"] {
        assert_eq!(
            kp1.private_key_pkcs8_pem_corrupt_deterministic(variant),
            kp2.private_key_pkcs8_pem_corrupt_deterministic(variant),
            "Deterministic PEM corruption should be stable for {variant}"
        );
    }
}

#[test]
fn corrupt_der_deterministic_is_stable() {
    let seed = Seed::from_env_value("ed25519-neg-det-der").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.ed25519("det-neg-der", Ed25519Spec::new());
    let kp2 = fx2.ed25519("det-neg-der", Ed25519Spec::new());

    for variant in ["corrupt:v1", "corrupt:v2", "corrupt:v3"] {
        assert_eq!(
            kp1.private_key_pkcs8_der_corrupt_deterministic(variant),
            kp2.private_key_pkcs8_der_corrupt_deterministic(variant),
            "Deterministic DER corruption should be stable for {variant}"
        );
    }
}

#[test]
fn mismatch_key_is_deterministic() {
    let seed = Seed::from_env_value("ed25519-neg-det-mm").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let mm1 = fx1
        .ed25519("det-mm", Ed25519Spec::new())
        .mismatched_public_key_spki_der();
    let mm2 = fx2
        .ed25519("det-mm", Ed25519Spec::new())
        .mismatched_public_key_spki_der();

    assert_eq!(mm1, mm2, "Mismatched key should be deterministic");
}

// =========================================================================
// Corrupt PEM variants are pairwise distinct
// =========================================================================

#[test]
fn corrupt_pem_variants_are_pairwise_distinct() {
    let fx = fx();
    let kp = fx.ed25519("neg-distinct", Ed25519Spec::new());

    let outputs: Vec<String> = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 15 },
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

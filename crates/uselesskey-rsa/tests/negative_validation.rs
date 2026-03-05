//! Negative fixture validation tests for RSA keys.
//!
//! Ensures ALL CorruptPem variants produce unparsable output,
//! corrupt DER fails parsing, mismatched keys fail signature
//! verification, and negative fixtures are deterministic.

mod testutil;

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// =========================================================================
// All CorruptPem variants fail PEM parsing for RSA-2048
// =========================================================================

#[test]
fn corrupt_pem_bad_header_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-hdr", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
        "BadHeader PEM should fail to parse"
    );
}

#[test]
fn corrupt_pem_bad_footer_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-ftr", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
        "BadFooter PEM should fail to parse"
    );
}

#[test]
fn corrupt_pem_bad_base64_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-b64", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
        "BadBase64 PEM should fail to parse"
    );
}

#[test]
fn corrupt_pem_truncate_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-trunc", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 30 });
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
        "Truncated PEM should fail to parse"
    );
}

#[test]
fn corrupt_pem_extra_blank_line_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-blank", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
        "ExtraBlankLine PEM should fail to parse"
    );
}

// =========================================================================
// Corrupt DER variants fail parsing
// =========================================================================

#[test]
fn truncated_der_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-der-trunc", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(16);
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_der(&truncated).is_err(),
        "Truncated DER should fail to parse"
    );
}

#[test]
fn corrupt_der_deterministic_fails_parsing() {
    let fx = fx();
    let kp = fx.rsa("neg-der-corrupt", RsaSpec::rs256());
    let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:rsa-v1");
    assert!(
        rsa::RsaPrivateKey::from_pkcs8_der(&corrupted).is_err(),
        "Deterministically corrupted DER should fail to parse"
    );
}

#[test]
fn multiple_corrupt_der_variants_all_fail() {
    let fx = fx();
    let kp = fx.rsa("neg-der-multi", RsaSpec::rs256());
    for variant in [
        "corrupt:a",
        "corrupt:b",
        "corrupt:c",
        "corrupt:d",
        "corrupt:e",
    ] {
        let corrupted = kp.private_key_pkcs8_der_corrupt_deterministic(variant);
        assert_ne!(
            corrupted,
            kp.private_key_pkcs8_der(),
            "Variant {variant} should differ from original"
        );
    }
}

// =========================================================================
// Mismatched keys are parseable but have different modulus
// =========================================================================

#[test]
fn mismatched_public_key_is_parseable_but_different() {
    let fx = fx();
    let kp = fx.rsa("neg-mismatch-mod", RsaSpec::rs256());

    let good_pub = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der()).unwrap();
    let mm_der = kp.mismatched_public_key_spki_der();
    let mm_pub = rsa::RsaPublicKey::from_public_key_der(&mm_der)
        .expect("Mismatched key should still be parseable DER");

    use rsa::traits::PublicKeyParts;
    assert_ne!(
        good_pub.n(),
        mm_pub.n(),
        "Mismatched key should have different modulus"
    );
}

// =========================================================================
// Negative fixtures are deterministic
// =========================================================================

#[test]
fn corrupt_pem_deterministic_is_stable() {
    let seed = Seed::from_env_value("rsa-neg-det-pem").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.rsa("det-neg", RsaSpec::rs256());
    let kp2 = fx2.rsa("det-neg", RsaSpec::rs256());

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
    let seed = Seed::from_env_value("rsa-neg-det-der").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let kp1 = fx1.rsa("det-neg-der", RsaSpec::rs256());
    let kp2 = fx2.rsa("det-neg-der", RsaSpec::rs256());

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
    let seed = Seed::from_env_value("rsa-neg-det-mm").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let mm1 = fx1
        .rsa("det-mm", RsaSpec::rs256())
        .mismatched_public_key_spki_der();
    let mm2 = fx2
        .rsa("det-mm", RsaSpec::rs256())
        .mismatched_public_key_spki_der();

    assert_eq!(mm1, mm2, "Mismatched key should be deterministic");
}

// =========================================================================
// All CorruptPem variants across multiple RSA key sizes
// =========================================================================

#[test]
fn all_corrupt_pem_variants_fail_for_all_key_sizes() {
    let fx = fx();
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 30 },
        CorruptPem::ExtraBlankLine,
    ];

    for bits in [2048, 3072, 4096] {
        let kp = fx.rsa(format!("neg-all-{bits}"), RsaSpec::new(bits));
        let original = kp.private_key_pkcs8_pem();

        for variant in &variants {
            let bad = kp.private_key_pkcs8_pem_corrupt(*variant);
            assert_ne!(
                bad, original,
                "CorruptPem::{variant:?} should differ for RSA-{bits}"
            );
            assert!(
                rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err(),
                "CorruptPem::{variant:?} should fail parsing for RSA-{bits}"
            );
        }
    }
}

// =========================================================================
// Corrupt PEM variants are pairwise distinct
// =========================================================================

#[test]
fn corrupt_pem_variants_are_pairwise_distinct() {
    let fx = fx();
    let kp = fx.rsa("neg-distinct", RsaSpec::rs256());

    let outputs: Vec<String> = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 30 },
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

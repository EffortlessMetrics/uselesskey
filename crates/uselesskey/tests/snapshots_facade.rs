//! Insta snapshot tests for the `uselesskey` facade crate.
//!
//! These tests verify that the facade re-exports work correctly and that
//! key metadata shapes are stable. **No actual key material is snapshotted.**

mod testutil;

use serde::Serialize;
use testutil::fx;

// =========================================================================
// Snapshot structs — metadata only, never key bytes
// =========================================================================

#[derive(Serialize)]
struct KeyPairShape {
    key_type: &'static str,
    algorithm: &'static str,
    pem_header: String,
    private_der_len: usize,
    public_der_len: usize,
    has_kid: bool,
    deterministic: bool,
}

#[derive(Serialize)]
struct HmacShape {
    algorithm: &'static str,
    secret_byte_len: usize,
    has_kid: bool,
    deterministic: bool,
}

#[derive(Serialize)]
struct TokenShape {
    kind: &'static str,
    value_len: usize,
    starts_with_prefix: bool,
    deterministic: bool,
}

#[derive(Serialize)]
struct FacadeMatrix {
    rsa: KeyPairShape,
    ecdsa: KeyPairShape,
    ed25519: KeyPairShape,
    hmac: HmacShape,
    token: TokenShape,
}

// =========================================================================
// RSA via facade
// =========================================================================

#[test]
#[cfg(feature = "rsa")]
fn snapshot_rsa_rs256_shape() {
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = fx();
    let kp = fx.rsa("snap-rsa", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();
    let first_line = pem.lines().next().unwrap_or("");

    let kp2 = fx.rsa("snap-rsa", RsaSpec::rs256());

    let shape = KeyPairShape {
        key_type: "RSA",
        algorithm: "RS256",
        pem_header: first_line.to_string(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
        #[cfg(feature = "jwk")]
        has_kid: !kp.kid().is_empty(),
        #[cfg(not(feature = "jwk"))]
        has_kid: false,
        deterministic: kp.private_key_pkcs8_pem() == kp2.private_key_pkcs8_pem(),
    };

    insta::assert_yaml_snapshot!("rsa_rs256_shape", shape, {
        ".private_der_len" => "[DER_LEN]",
        ".public_der_len" => "[DER_LEN]",
    });
}

// =========================================================================
// ECDSA via facade (P-256)
// =========================================================================

#[test]
#[cfg(feature = "ecdsa")]
fn snapshot_ecdsa_p256_shape() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    let fx = fx();
    let kp = fx.ecdsa("snap-ecdsa", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();
    let first_line = pem.lines().next().unwrap_or("");

    let kp2 = fx.ecdsa("snap-ecdsa", EcdsaSpec::es256());

    let shape = KeyPairShape {
        key_type: "EC",
        algorithm: "ES256",
        pem_header: first_line.to_string(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
        #[cfg(feature = "jwk")]
        has_kid: !kp.kid().is_empty(),
        #[cfg(not(feature = "jwk"))]
        has_kid: false,
        deterministic: kp.private_key_pkcs8_pem() == kp2.private_key_pkcs8_pem(),
    };

    insta::assert_yaml_snapshot!("ecdsa_p256_shape", shape, {
        ".private_der_len" => "[DER_LEN]",
        ".public_der_len" => "[DER_LEN]",
    });
}

// =========================================================================
// Ed25519 via facade
// =========================================================================

#[test]
#[cfg(feature = "ed25519")]
fn snapshot_ed25519_shape() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    let fx = fx();
    let kp = fx.ed25519("snap-ed25519", Ed25519Spec::new());
    let pem = kp.private_key_pkcs8_pem();
    let first_line = pem.lines().next().unwrap_or("");

    let kp2 = fx.ed25519("snap-ed25519", Ed25519Spec::new());

    let shape = KeyPairShape {
        key_type: "OKP",
        algorithm: "EdDSA",
        pem_header: first_line.to_string(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
        #[cfg(feature = "jwk")]
        has_kid: !kp.kid().is_empty(),
        #[cfg(not(feature = "jwk"))]
        has_kid: false,
        deterministic: kp.private_key_pkcs8_pem() == kp2.private_key_pkcs8_pem(),
    };

    insta::assert_yaml_snapshot!("ed25519_shape", shape, {
        ".private_der_len" => "[DER_LEN]",
        ".public_der_len" => "[DER_LEN]",
    });
}

// =========================================================================
// HMAC via facade (HS256)
// =========================================================================

#[test]
#[cfg(feature = "hmac")]
fn snapshot_hmac_hs256_shape() {
    use uselesskey::{HmacFactoryExt, HmacSpec};

    let fx = fx();
    let secret = fx.hmac("snap-hmac", HmacSpec::hs256());
    let secret2 = fx.hmac("snap-hmac", HmacSpec::hs256());

    let shape = HmacShape {
        algorithm: "HS256",
        secret_byte_len: secret.secret_bytes().len(),
        #[cfg(feature = "jwk")]
        has_kid: !secret.kid().is_empty(),
        #[cfg(not(feature = "jwk"))]
        has_kid: false,
        deterministic: secret.secret_bytes() == secret2.secret_bytes(),
    };

    insta::assert_yaml_snapshot!("hmac_hs256_shape", shape);
}

// =========================================================================
// Token via facade
// =========================================================================

#[test]
#[cfg(feature = "token")]
fn snapshot_token_api_key_shape() {
    use uselesskey::{TokenFactoryExt, TokenSpec};

    let fx = fx();
    let tok = fx.token("snap-token", TokenSpec::api_key());
    let tok2 = fx.token("snap-token", TokenSpec::api_key());

    let shape = TokenShape {
        kind: "api_key",
        value_len: tok.value().len(),
        starts_with_prefix: tok.value().starts_with("uk_test_"),
        deterministic: tok.value() == tok2.value(),
    };

    insta::assert_yaml_snapshot!("token_api_key_shape", shape);
}

// =========================================================================
// Full facade matrix — all key types in one snapshot
// =========================================================================

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
    feature = "token",
    feature = "jwk",
))]
fn snapshot_facade_matrix() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec,
    };

    let fx = fx();

    let rsa = fx.rsa("matrix", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("matrix", EcdsaSpec::es256());
    let ed = fx.ed25519("matrix", Ed25519Spec::new());
    let hmac = fx.hmac("matrix", HmacSpec::hs256());
    let tok = fx.token("matrix", TokenSpec::api_key());

    let matrix = FacadeMatrix {
        rsa: KeyPairShape {
            key_type: "RSA",
            algorithm: "RS256",
            pem_header: rsa
                .private_key_pkcs8_pem()
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
            private_der_len: rsa.private_key_pkcs8_der().len(),
            public_der_len: rsa.public_key_spki_der().len(),
            has_kid: !rsa.kid().is_empty(),
            deterministic: true,
        },
        ecdsa: KeyPairShape {
            key_type: "EC",
            algorithm: "ES256",
            pem_header: ecdsa
                .private_key_pkcs8_pem()
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
            private_der_len: ecdsa.private_key_pkcs8_der().len(),
            public_der_len: ecdsa.public_key_spki_der().len(),
            has_kid: !ecdsa.kid().is_empty(),
            deterministic: true,
        },
        ed25519: KeyPairShape {
            key_type: "OKP",
            algorithm: "EdDSA",
            pem_header: ed
                .private_key_pkcs8_pem()
                .lines()
                .next()
                .unwrap_or("")
                .to_string(),
            private_der_len: ed.private_key_pkcs8_der().len(),
            public_der_len: ed.public_key_spki_der().len(),
            has_kid: !ed.kid().is_empty(),
            deterministic: true,
        },
        hmac: HmacShape {
            algorithm: "HS256",
            secret_byte_len: hmac.secret_bytes().len(),
            has_kid: !hmac.kid().is_empty(),
            deterministic: true,
        },
        token: TokenShape {
            kind: "api_key",
            value_len: tok.value().len(),
            starts_with_prefix: tok.value().starts_with("uk_test_"),
            deterministic: true,
        },
    };

    insta::assert_yaml_snapshot!("facade_matrix", matrix, {
        ".rsa.private_der_len" => "[DER_LEN]",
        ".rsa.public_der_len" => "[DER_LEN]",
        ".ecdsa.private_der_len" => "[DER_LEN]",
        ".ecdsa.public_der_len" => "[DER_LEN]",
        ".ed25519.private_der_len" => "[DER_LEN]",
        ".ed25519.public_der_len" => "[DER_LEN]",
    });
}

// =========================================================================
// Re-export accessibility — types from sub-crates via facade
// =========================================================================

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn snapshot_reexport_jwk_via_facade() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    let fx = fx();
    let kp = fx.rsa("jwk-reexport", RsaSpec::rs256());
    let jwk = kp.public_jwk();
    let jwks = JwksBuilder::new().add_public(jwk).build();

    #[derive(Serialize)]
    struct JwksShape {
        key_count: usize,
        kty: String,
        alg: String,
        has_kid: bool,
    }

    let val = jwks.to_value();
    let first_key = &val["keys"][0];

    let shape = JwksShape {
        key_count: val["keys"].as_array().map_or(0, |a| a.len()),
        kty: first_key["kty"].as_str().unwrap_or("").to_string(),
        alg: first_key["alg"].as_str().unwrap_or("").to_string(),
        has_kid: first_key.get("kid").is_some(),
    };

    insta::assert_yaml_snapshot!("reexport_jwk_shape", shape);
}

#[test]
fn snapshot_reexport_negative_via_facade() {
    use uselesskey::negative::CorruptPem;

    #[derive(Serialize)]
    struct NegativeReexport {
        bad_header_available: bool,
        bad_footer_available: bool,
        bad_base64_available: bool,
    }

    let pem = "-----BEGIN PRIVATE KEY-----\nAAA=\n-----END PRIVATE KEY-----\n";

    let shape = NegativeReexport {
        bad_header_available: uselesskey::negative::corrupt_pem(pem, CorruptPem::BadHeader)
            .contains("CORRUPTED"),
        bad_footer_available: uselesskey::negative::corrupt_pem(pem, CorruptPem::BadFooter)
            .contains("CORRUPTED"),
        bad_base64_available: uselesskey::negative::corrupt_pem(pem, CorruptPem::BadBase64)
            .contains("!!!CORRUPTBASE64!!!"),
    };

    insta::assert_yaml_snapshot!("reexport_negative", shape);
}

// =========================================================================
// Label divergence — different labels produce different keys
// =========================================================================

#[derive(Serialize)]
struct LabelDivergence {
    key_type: &'static str,
    labels_differ: bool,
}

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
))]
fn snapshot_label_divergence() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        RsaFactoryExt, RsaSpec,
    };

    let fx = fx();

    let entries = vec![
        LabelDivergence {
            key_type: "RSA",
            labels_differ: {
                let a = fx.rsa("label-a", RsaSpec::rs256());
                let b = fx.rsa("label-b", RsaSpec::rs256());
                a.private_key_pkcs8_pem() != b.private_key_pkcs8_pem()
            },
        },
        LabelDivergence {
            key_type: "ECDSA",
            labels_differ: {
                let a = fx.ecdsa("label-a", EcdsaSpec::es256());
                let b = fx.ecdsa("label-b", EcdsaSpec::es256());
                a.private_key_pkcs8_pem() != b.private_key_pkcs8_pem()
            },
        },
        LabelDivergence {
            key_type: "Ed25519",
            labels_differ: {
                let a = fx.ed25519("label-a", Ed25519Spec::new());
                let b = fx.ed25519("label-b", Ed25519Spec::new());
                a.private_key_pkcs8_pem() != b.private_key_pkcs8_pem()
            },
        },
        LabelDivergence {
            key_type: "HMAC",
            labels_differ: {
                let a = fx.hmac("label-a", HmacSpec::hs256());
                let b = fx.hmac("label-b", HmacSpec::hs256());
                a.secret_bytes() != b.secret_bytes()
            },
        },
    ];

    insta::assert_yaml_snapshot!("facade_label_divergence", entries);
}

// =========================================================================
// Debug safety — Debug output must never leak key material
// =========================================================================

#[derive(Serialize)]
struct DebugSafety {
    key_type: &'static str,
    contains_struct_name: bool,
    leaks_pem_header: bool,
}

#[test]
#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
fn snapshot_debug_safety() {
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, RsaFactoryExt, RsaSpec,
    };

    let fx = fx();

    let entries = vec![
        {
            let kp = fx.rsa("debug-rsa", RsaSpec::rs256());
            let dbg = format!("{kp:?}");
            DebugSafety {
                key_type: "RSA",
                contains_struct_name: dbg.contains("RsaKeyPair"),
                leaks_pem_header: dbg.contains("BEGIN PRIVATE KEY"),
            }
        },
        {
            let kp = fx.ecdsa("debug-ecdsa", EcdsaSpec::es256());
            let dbg = format!("{kp:?}");
            DebugSafety {
                key_type: "ECDSA",
                contains_struct_name: dbg.contains("EcdsaKeyPair"),
                leaks_pem_header: dbg.contains("BEGIN PRIVATE KEY"),
            }
        },
        {
            let kp = fx.ed25519("debug-ed25519", Ed25519Spec::new());
            let dbg = format!("{kp:?}");
            DebugSafety {
                key_type: "Ed25519",
                contains_struct_name: dbg.contains("Ed25519KeyPair"),
                leaks_pem_header: dbg.contains("BEGIN PRIVATE KEY"),
            }
        },
    ];

    insta::assert_yaml_snapshot!("facade_debug_safety", entries);
}

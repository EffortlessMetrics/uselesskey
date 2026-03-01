//! Insta snapshot tests for uselesskey-ecdsa.
//!
//! These tests snapshot keypair shapes produced by deterministic keys
//! to detect unintended changes in ECDSA output format or metadata.
//! Key material bytes are NEVER snapshotted — only structural metadata.

use std::sync::OnceLock;

use serde::Serialize;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| Factory::deterministic(Seed::new([0xAB; 32])))
        .clone()
}

// =========================================================================
// Snapshot structs
// =========================================================================

#[derive(Serialize)]
struct PemShape {
    curve: &'static str,
    private_pem_header: String,
    private_pem_has_footer: bool,
    private_pem_line_count: usize,
    public_pem_header: String,
    public_pem_has_footer: bool,
    public_pem_line_count: usize,
    private_der_len: usize,
    public_der_len: usize,
}

#[derive(Serialize)]
struct JwkShape {
    curve: &'static str,
    kty: String,
    crv: String,
    alg: String,
    use_: String,
    kid_len: usize,
    has_x: bool,
    has_y: bool,
    x_byte_len: usize,
    y_byte_len: usize,
}

#[derive(Serialize)]
struct PrivateJwkShape {
    curve: &'static str,
    kty: String,
    crv: String,
    alg: String,
    has_d: bool,
    d_byte_len: usize,
}

#[derive(Serialize)]
struct JwksShape {
    curve: &'static str,
    key_count: usize,
    first_key_kty: String,
    first_key_crv: String,
}

#[derive(Serialize)]
struct NegativeMismatch {
    curve: &'static str,
    mismatch_der_parseable: bool,
    mismatch_differs_from_good: bool,
}

#[derive(Serialize)]
struct NegativeCorruptPem {
    curve: &'static str,
    variant: &'static str,
    contains_begin_private_key: bool,
    contains_begin_corrupted: bool,
    differs_from_good: bool,
}

#[derive(Serialize)]
struct NegativeTruncatedDer {
    curve: &'static str,
    requested_len: usize,
    actual_len: usize,
    shorter_than_original: bool,
}

#[derive(Serialize)]
struct LabelDivergence {
    curve: &'static str,
    private_keys_differ: bool,
    public_keys_differ: bool,
}

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_private_key_material: bool,
    uses_non_exhaustive: bool,
}

#[derive(Serialize)]
struct SpecMatrix {
    curve: &'static str,
    alg: &'static str,
    deterministic: bool,
    private_pem_starts_with_begin: bool,
    public_pem_starts_with_begin: bool,
}

// =========================================================================
// PEM shape snapshots (both curves)
// =========================================================================

fn extract_first_line(pem: &str) -> String {
    pem.lines().next().unwrap_or("").to_string()
}

#[test]
fn snapshot_pem_shape_p256() {
    let fx = fx();
    let kp = fx.ecdsa("snap-pem", EcdsaSpec::es256());

    let result = PemShape {
        curve: "P-256",
        private_pem_header: extract_first_line(kp.private_key_pkcs8_pem()),
        private_pem_has_footer: kp
            .private_key_pkcs8_pem()
            .contains("-----END PRIVATE KEY-----"),
        private_pem_line_count: kp.private_key_pkcs8_pem().lines().count(),
        public_pem_header: extract_first_line(kp.public_key_spki_pem()),
        public_pem_has_footer: kp
            .public_key_spki_pem()
            .contains("-----END PUBLIC KEY-----"),
        public_pem_line_count: kp.public_key_spki_pem().lines().count(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("pem_shape_p256", result);
}

#[test]
fn snapshot_pem_shape_p384() {
    let fx = fx();
    let kp = fx.ecdsa("snap-pem", EcdsaSpec::es384());

    let result = PemShape {
        curve: "P-384",
        private_pem_header: extract_first_line(kp.private_key_pkcs8_pem()),
        private_pem_has_footer: kp
            .private_key_pkcs8_pem()
            .contains("-----END PRIVATE KEY-----"),
        private_pem_line_count: kp.private_key_pkcs8_pem().lines().count(),
        public_pem_header: extract_first_line(kp.public_key_spki_pem()),
        public_pem_has_footer: kp
            .public_key_spki_pem()
            .contains("-----END PUBLIC KEY-----"),
        public_pem_line_count: kp.public_key_spki_pem().lines().count(),
        private_der_len: kp.private_key_pkcs8_der().len(),
        public_der_len: kp.public_key_spki_der().len(),
    };

    insta::assert_yaml_snapshot!("pem_shape_p384", result);
}

// =========================================================================
// JWK shape snapshots (both curves)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_snapshots {
    use super::*;

    fn decode_b64url_len(s: &str) -> usize {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.decode(s).map(|b| b.len()).unwrap_or(0)
    }

    #[test]
    fn snapshot_public_jwk_p256() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwk", EcdsaSpec::es256());
        let jwk = kp.public_jwk().to_value();

        let result = JwkShape {
            curve: "P-256",
            kty: jwk["kty"].as_str().unwrap_or("").to_string(),
            crv: jwk["crv"].as_str().unwrap_or("").to_string(),
            alg: jwk["alg"].as_str().unwrap_or("").to_string(),
            use_: jwk["use"].as_str().unwrap_or("").to_string(),
            kid_len: jwk["kid"].as_str().map_or(0, str::len),
            has_x: jwk["x"].is_string(),
            has_y: jwk["y"].is_string(),
            x_byte_len: jwk["x"].as_str().map_or(0, decode_b64url_len),
            y_byte_len: jwk["y"].as_str().map_or(0, decode_b64url_len),
        };

        insta::assert_yaml_snapshot!("public_jwk_p256", result);
    }

    #[test]
    fn snapshot_public_jwk_p384() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwk", EcdsaSpec::es384());
        let jwk = kp.public_jwk().to_value();

        let result = JwkShape {
            curve: "P-384",
            kty: jwk["kty"].as_str().unwrap_or("").to_string(),
            crv: jwk["crv"].as_str().unwrap_or("").to_string(),
            alg: jwk["alg"].as_str().unwrap_or("").to_string(),
            use_: jwk["use"].as_str().unwrap_or("").to_string(),
            kid_len: jwk["kid"].as_str().map_or(0, str::len),
            has_x: jwk["x"].is_string(),
            has_y: jwk["y"].is_string(),
            x_byte_len: jwk["x"].as_str().map_or(0, decode_b64url_len),
            y_byte_len: jwk["y"].as_str().map_or(0, decode_b64url_len),
        };

        insta::assert_yaml_snapshot!("public_jwk_p384", result);
    }

    #[test]
    fn snapshot_private_jwk_p256() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwk-priv", EcdsaSpec::es256());
        let jwk = kp.private_key_jwk().to_value();

        let result = PrivateJwkShape {
            curve: "P-256",
            kty: jwk["kty"].as_str().unwrap_or("").to_string(),
            crv: jwk["crv"].as_str().unwrap_or("").to_string(),
            alg: jwk["alg"].as_str().unwrap_or("").to_string(),
            has_d: jwk["d"].is_string(),
            d_byte_len: jwk["d"].as_str().map_or(0, decode_b64url_len),
        };

        insta::assert_yaml_snapshot!("private_jwk_p256", result);
    }

    #[test]
    fn snapshot_private_jwk_p384() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwk-priv", EcdsaSpec::es384());
        let jwk = kp.private_key_jwk().to_value();

        let result = PrivateJwkShape {
            curve: "P-384",
            kty: jwk["kty"].as_str().unwrap_or("").to_string(),
            crv: jwk["crv"].as_str().unwrap_or("").to_string(),
            alg: jwk["alg"].as_str().unwrap_or("").to_string(),
            has_d: jwk["d"].is_string(),
            d_byte_len: jwk["d"].as_str().map_or(0, decode_b64url_len),
        };

        insta::assert_yaml_snapshot!("private_jwk_p384", result);
    }

    #[test]
    fn snapshot_jwks_p256() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwks", EcdsaSpec::es256());
        let jwks = kp.public_jwks_json();
        let keys = jwks["keys"].as_array().expect("keys array");

        let result = JwksShape {
            curve: "P-256",
            key_count: keys.len(),
            first_key_kty: keys[0]["kty"].as_str().unwrap_or("").to_string(),
            first_key_crv: keys[0]["crv"].as_str().unwrap_or("").to_string(),
        };

        insta::assert_yaml_snapshot!("jwks_p256", result);
    }

    #[test]
    fn snapshot_jwks_p384() {
        let fx = fx();
        let kp = fx.ecdsa("snap-jwks", EcdsaSpec::es384());
        let jwks = kp.public_jwks_json();
        let keys = jwks["keys"].as_array().expect("keys array");

        let result = JwksShape {
            curve: "P-384",
            key_count: keys.len(),
            first_key_kty: keys[0]["kty"].as_str().unwrap_or("").to_string(),
            first_key_crv: keys[0]["crv"].as_str().unwrap_or("").to_string(),
        };

        insta::assert_yaml_snapshot!("jwks_p384", result);
    }
}

// =========================================================================
// Negative fixture snapshots
// =========================================================================

#[test]
fn snapshot_mismatch_public_key() {
    let fx = fx();

    let entries: Vec<NegativeMismatch> = [EcdsaSpec::es256(), EcdsaSpec::es384()]
        .into_iter()
        .map(|spec| {
            let kp = fx.ecdsa("snap-mismatch", spec);
            let good_pub = kp.public_key_spki_der();
            let bad_pub = kp.mismatched_public_key_spki_der();

            NegativeMismatch {
                curve: spec.curve_name(),
                mismatch_der_parseable: !bad_pub.is_empty(),
                mismatch_differs_from_good: good_pub != bad_pub.as_slice(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("mismatch_public_key", entries);
}

#[test]
fn snapshot_corrupt_pem_bad_header() {
    let fx = fx();

    let entries: Vec<NegativeCorruptPem> = [EcdsaSpec::es256(), EcdsaSpec::es384()]
        .into_iter()
        .map(|spec| {
            let kp = fx.ecdsa("snap-corrupt", spec);
            let good = kp.private_key_pkcs8_pem();
            let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

            NegativeCorruptPem {
                curve: spec.curve_name(),
                variant: "BadHeader",
                contains_begin_private_key: bad.contains("-----BEGIN PRIVATE KEY-----"),
                contains_begin_corrupted: bad.contains("-----BEGIN CORRUPTED KEY-----"),
                differs_from_good: bad != good,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("corrupt_pem_bad_header", entries);
}

#[test]
fn snapshot_corrupt_pem_bad_base64() {
    let fx = fx();

    let entries: Vec<NegativeCorruptPem> = [EcdsaSpec::es256(), EcdsaSpec::es384()]
        .into_iter()
        .map(|spec| {
            let kp = fx.ecdsa("snap-corrupt", spec);
            let good = kp.private_key_pkcs8_pem();
            let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);

            NegativeCorruptPem {
                curve: spec.curve_name(),
                variant: "BadBase64",
                contains_begin_private_key: bad.contains("-----BEGIN PRIVATE KEY-----"),
                contains_begin_corrupted: bad.contains("-----BEGIN CORRUPTED KEY-----"),
                differs_from_good: bad != good,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("corrupt_pem_bad_base64", entries);
}

#[test]
fn snapshot_truncated_der() {
    let fx = fx();

    let entries: Vec<NegativeTruncatedDer> = [EcdsaSpec::es256(), EcdsaSpec::es384()]
        .into_iter()
        .map(|spec| {
            let kp = fx.ecdsa("snap-truncate", spec);
            let full_len = kp.private_key_pkcs8_der().len();
            let truncated = kp.private_key_pkcs8_der_truncated(10);

            NegativeTruncatedDer {
                curve: spec.curve_name(),
                requested_len: 10,
                actual_len: truncated.len(),
                shorter_than_original: truncated.len() < full_len,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("truncated_der", entries);
}

// =========================================================================
// Spec matrix snapshot
// =========================================================================

#[test]
fn snapshot_spec_matrix() {
    let fx = fx();

    let entries: Vec<SpecMatrix> = [
        ("P-256", "ES256", EcdsaSpec::es256()),
        ("P-384", "ES384", EcdsaSpec::es384()),
    ]
    .into_iter()
    .map(|(curve, alg, spec)| {
        let k1 = fx.ecdsa("matrix-label", spec);
        let k2 = fx.ecdsa("matrix-label", spec);

        SpecMatrix {
            curve,
            alg,
            deterministic: k1.private_key_pkcs8_der() == k2.private_key_pkcs8_der(),
            private_pem_starts_with_begin: k1.private_key_pkcs8_pem().starts_with("-----BEGIN "),
            public_pem_starts_with_begin: k1.public_key_spki_pem().starts_with("-----BEGIN "),
        }
    })
    .collect();

    insta::assert_yaml_snapshot!("spec_matrix", entries);
}

// =========================================================================
// Label divergence snapshot
// =========================================================================

#[test]
fn snapshot_label_divergence() {
    let fx = fx();

    let entries: Vec<LabelDivergence> = [EcdsaSpec::es256(), EcdsaSpec::es384()]
        .into_iter()
        .map(|spec| {
            let a = fx.ecdsa("label-a", spec);
            let b = fx.ecdsa("label-b", spec);

            LabelDivergence {
                curve: spec.curve_name(),
                private_keys_differ: a.private_key_pkcs8_der() != b.private_key_pkcs8_der(),
                public_keys_differ: a.public_key_spki_der() != b.public_key_spki_der(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("label_divergence", entries);
}

// =========================================================================
// Debug safety snapshot
// =========================================================================

#[test]
fn snapshot_debug_safety() {
    let fx = fx();
    let kp = fx.ecdsa("debug-snap", EcdsaSpec::es256());
    let dbg = format!("{kp:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("EcdsaKeyPair"),
        contains_label: dbg.contains("debug-snap"),
        contains_private_key_material: dbg.contains(kp.private_key_pkcs8_pem()),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("debug_safety", result);
}

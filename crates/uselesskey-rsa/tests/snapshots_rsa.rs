//! Insta snapshot tests for uselesskey-rsa.
//!
//! These tests snapshot RSA key *metadata* (PEM header types, key lengths,
//! algorithm names, kid format) produced by deterministic keys to detect
//! unintended changes in output shape. Actual key bytes are NEVER snapshotted.

use std::sync::OnceLock;

use serde::Serialize;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// =========================================================================
// Deterministic factory (shared across tests)
// =========================================================================

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| Factory::deterministic(Seed::new([0xAB; 32])))
        .clone()
}

// =========================================================================
// Snapshot helper structs
// =========================================================================

#[derive(Serialize)]
struct PemShape {
    label: &'static str,
    spec_name: &'static str,
    bits: usize,
    private_pem_first_line: String,
    private_pem_last_line: String,
    private_der_len: usize,
    public_pem_first_line: String,
    public_pem_last_line: String,
    public_der_len: usize,
}

#[derive(Serialize)]
#[derive(Serialize)]
struct SpecMatrixEntry {
    spec_name: &'static str,
    bits: usize,
    private_der_len: usize,
    public_der_len: usize,
    deterministic: bool,
}

#[derive(Serialize)]
struct LabelDivergence {
    spec_name: &'static str,
    private_keys_differ: bool,
    public_keys_differ: bool,
}

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_private_key_marker: bool,
    uses_non_exhaustive: bool,
}

#[derive(Serialize)]
struct MismatchShape {
    spec_name: &'static str,
    good_public_der_len: usize,
    mismatched_public_der_len: usize,
    keys_differ: bool,
}

#[derive(Serialize)]
struct CorruptPemShape {
    variant: &'static str,
    first_line: String,
    differs_from_original: bool,
}

// =========================================================================
// PEM shape snapshots — all specs
// =========================================================================

fn pem_first_line(pem: &str) -> String {
    pem.lines().next().unwrap_or("").to_string()
}

fn pem_last_line(pem: &str) -> String {
    pem.lines().last().unwrap_or("").to_string()
}

fn all_specs() -> Vec<(&'static str, RsaSpec)> {
    vec![
        ("RS256", RsaSpec::rs256()),
        ("RS384", RsaSpec::new(3072)),
        ("RS512", RsaSpec::new(4096)),
        // PS variants use the same key sizes; only signing padding differs.
        ("PS256", RsaSpec::rs256()),
        ("PS384", RsaSpec::new(3072)),
        ("PS512", RsaSpec::new(4096)),
    ]
}

#[test]
fn snapshot_pem_shapes() {
    let fx = fx();

    let shapes: Vec<PemShape> = all_specs()
        .into_iter()
        .map(|(name, spec)| {
            let label = format!("snap-pem-{name}");
            let kp = fx.rsa(&label, spec);
            PemShape {
                label: match name {
                    "RS256" => "snap-pem-RS256",
                    "RS384" => "snap-pem-RS384",
                    "RS512" => "snap-pem-RS512",
                    "PS256" => "snap-pem-PS256",
                    "PS384" => "snap-pem-PS384",
                    "PS512" => "snap-pem-PS512",
                    _ => unreachable!(),
                },
                spec_name: name,
                bits: spec.bits,
                private_pem_first_line: pem_first_line(kp.private_key_pkcs8_pem()),
                private_pem_last_line: pem_last_line(kp.private_key_pkcs8_pem()),
                private_der_len: kp.private_key_pkcs8_der().len(),
                public_pem_first_line: pem_first_line(kp.public_key_spki_pem()),
                public_pem_last_line: pem_last_line(kp.public_key_spki_pem()),
                public_der_len: kp.public_key_spki_der().len(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("pem_shapes", shapes);
}

// =========================================================================
// Spec matrix — determinism and key sizes
// =========================================================================

#[test]
fn snapshot_spec_matrix() {
    let fx = fx();

    let entries: Vec<SpecMatrixEntry> = all_specs()
        .into_iter()
        .map(|(name, spec)| {
            let label = format!("matrix-{name}");
            let k1 = fx.rsa(&label, spec);
            let k2 = fx.rsa(&label, spec);

            SpecMatrixEntry {
                spec_name: name,
                bits: spec.bits,
                private_der_len: k1.private_key_pkcs8_der().len(),
                public_der_len: k1.public_key_spki_der().len(),
                deterministic: k1.private_key_pkcs8_der() == k2.private_key_pkcs8_der(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("spec_matrix", entries);
}

// =========================================================================
// Label divergence — different labels produce different keys
// =========================================================================

#[test]
fn snapshot_label_divergence() {
    let fx = fx();

    let entries: Vec<LabelDivergence> = all_specs()
        .into_iter()
        .map(|(name, spec)| {
            let a = fx.rsa("label-a", spec);
            let b = fx.rsa("label-b", spec);
            LabelDivergence {
                spec_name: name,
                private_keys_differ: a.private_key_pkcs8_der() != b.private_key_pkcs8_der(),
                public_keys_differ: a.public_key_spki_der() != b.public_key_spki_der(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("label_divergence", entries);
}

// =========================================================================
// Debug safety — no key material leaked
// =========================================================================

#[test]
fn snapshot_debug_safety() {
    let fx = fx();
    let kp = fx.rsa("debug-snap", RsaSpec::rs256());
    let dbg = format!("{kp:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("RsaKeyPair"),
        contains_label: dbg.contains("debug-snap"),
        contains_private_key_marker: dbg.contains("BEGIN PRIVATE KEY"),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("debug_safety", result);
}

// =========================================================================
// Mismatch variant — mismatched public key
// =========================================================================

#[test]
fn snapshot_mismatch_variant() {
    let fx = fx();

    let specs: Vec<(&str, RsaSpec)> =
        vec![("RS256", RsaSpec::rs256()), ("RS512", RsaSpec::new(4096))];

    let entries: Vec<MismatchShape> = specs
        .into_iter()
        .map(|(name, spec)| {
            let kp = fx.rsa("mismatch-snap", spec);
            let good = kp.public_key_spki_der();
            let bad = kp.mismatched_public_key_spki_der();
            MismatchShape {
                spec_name: name,
                good_public_der_len: good.len(),
                mismatched_public_der_len: bad.len(),
                keys_differ: good != bad.as_slice(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("mismatch_variant", entries);
}

// =========================================================================
// Corrupt PEM variants
// =========================================================================

#[test]
fn snapshot_corrupt_pem_variants() {
    let fx = fx();
    let kp = fx.rsa("corrupt-snap", RsaSpec::rs256());
    let original = kp.private_key_pkcs8_pem();

    let variants: Vec<CorruptPemShape> = vec![
        (
            "BadHeader",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        ),
        (
            "BadFooter",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        ),
        (
            "BadBase64",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        ),
        (
            "ExtraBlankLine",
            kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
        ),
    ]
    .into_iter()
    .map(|(name, corrupted)| CorruptPemShape {
        variant: name,
        first_line: pem_first_line(&corrupted),
        differs_from_original: corrupted != original,
    })
    .collect();

    insta::assert_yaml_snapshot!("corrupt_pem_variants", variants);
}

// =========================================================================
// Truncated DER
// =========================================================================

#[derive(Serialize)]
struct TruncatedDerShape {
    original_len: usize,
    truncated_len: usize,
}

#[test]
fn snapshot_truncated_der() {
    let fx = fx();
    let kp = fx.rsa("trunc-snap", RsaSpec::rs256());

    let result = TruncatedDerShape {
        original_len: kp.private_key_pkcs8_der().len(),
        truncated_len: kp.private_key_pkcs8_der_truncated(10).len(),
    };

    insta::assert_yaml_snapshot!("truncated_der", result);
}

// =========================================================================
// JWK structure (feature-gated)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct JwkShape {
        spec_name: &'static str,
        kty: String,
        alg: String,
        use_: String,
        kid_len: usize,
        kid_is_base64url_shaped: bool,
        has_n: bool,
        has_e: bool,
    }

    #[derive(Serialize)]
    struct JwksShape {
        spec_name: &'static str,
        has_keys_array: bool,
        keys_count: usize,
        first_key_kty: String,
        first_key_alg: String,
    }

    #[derive(Serialize)]
    struct PrivateJwkShape {
        kty: String,
        alg: String,
        has_d: bool,
        has_p: bool,
        has_q: bool,
        has_dp: bool,
        has_dq: bool,
        has_qi: bool,
    }

    #[test]
    fn snapshot_jwk_shapes() {
        let fx = fx();

        let specs: Vec<(&str, RsaSpec)> = vec![
            ("RS256", RsaSpec::rs256()),
            ("RS384", RsaSpec::new(3072)),
            ("RS512", RsaSpec::new(4096)),
        ];

        let entries: Vec<JwkShape> = specs
            .into_iter()
            .map(|(name, spec)| {
                let label = format!("jwk-snap-{name}");
                let kp = fx.rsa(&label, spec);
                let jwk = kp.public_jwk_json();
                let kid = kp.kid();

                JwkShape {
                    spec_name: name,
                    kty: jwk["kty"].as_str().unwrap_or("").to_string(),
                    alg: jwk["alg"].as_str().unwrap_or("").to_string(),
                    use_: jwk["use"].as_str().unwrap_or("").to_string(),
                    kid_len: kid.len(),
                    kid_is_base64url_shaped: kid
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                    has_n: jwk.get("n").is_some(),
                    has_e: jwk.get("e").is_some(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("jwk_shapes", entries);
    }

    #[test]
    fn snapshot_jwks_shapes() {
        let fx = fx();

        let specs: Vec<(&str, RsaSpec)> = vec![
            ("RS256", RsaSpec::rs256()),
            ("RS384", RsaSpec::new(3072)),
            ("RS512", RsaSpec::new(4096)),
        ];

        let entries: Vec<JwksShape> = specs
            .into_iter()
            .map(|(name, spec)| {
                let label = format!("jwks-snap-{name}");
                let kp = fx.rsa(&label, spec);
                let jwks = kp.public_jwks_json();
                let keys = jwks["keys"].as_array();

                JwksShape {
                    spec_name: name,
                    has_keys_array: keys.is_some(),
                    keys_count: keys.map_or(0, |a| a.len()),
                    first_key_kty: keys
                        .and_then(|a| a.first())
                        .and_then(|k| k["kty"].as_str())
                        .unwrap_or("")
                        .to_string(),
                    first_key_alg: keys
                        .and_then(|a| a.first())
                        .and_then(|k| k["alg"].as_str())
                        .unwrap_or("")
                        .to_string(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("jwks_shapes", entries);
    }

    #[test]
    fn snapshot_private_jwk_shape() {
        let fx = fx();
        let kp = fx.rsa("priv-jwk-snap", RsaSpec::rs256());
        let jwk = kp.private_key_jwk_json();

        let result = PrivateJwkShape {
            kty: jwk["kty"].as_str().unwrap_or("").to_string(),
            alg: jwk["alg"].as_str().unwrap_or("").to_string(),
            has_d: jwk.get("d").is_some(),
            has_p: jwk.get("p").is_some(),
            has_q: jwk.get("q").is_some(),
            has_dp: jwk.get("dp").is_some(),
            has_dq: jwk.get("dq").is_some(),
            has_qi: jwk.get("qi").is_some(),
        };

        insta::assert_yaml_snapshot!("private_jwk_shape", result);
    }
}

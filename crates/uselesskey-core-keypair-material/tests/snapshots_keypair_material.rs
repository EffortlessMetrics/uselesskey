//! Insta snapshot tests for uselesskey-core-keypair-material.
//!
//! Snapshot material type metadata — field lengths, Debug redaction,
//! corruption shapes. All key material is redacted.

use serde::Serialize;
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

fn sample_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    )
}

#[derive(Serialize)]
struct MaterialShape {
    pkcs8_der_len: usize,
    pkcs8_pem_len: usize,
    spki_der_len: usize,
    spki_pem_len: usize,
}

#[test]
fn snapshot_material_field_lengths() {
    let m = sample_material();
    let result = MaterialShape {
        pkcs8_der_len: m.private_key_pkcs8_der().len(),
        pkcs8_pem_len: m.private_key_pkcs8_pem().len(),
        spki_der_len: m.public_key_spki_der().len(),
        spki_pem_len: m.public_key_spki_pem().len(),
    };
    insta::assert_yaml_snapshot!("keypair_material_field_lengths", result);
}

#[test]
fn snapshot_debug_redaction() {
    let m = sample_material();
    let dbg = format!("{m:?}");

    #[derive(Serialize)]
    struct DebugShape {
        contains_struct_name: bool,
        leaks_private_key: bool,
        leaks_public_key: bool,
        contains_len_fields: bool,
    }

    let result = DebugShape {
        contains_struct_name: dbg.contains("Pkcs8SpkiKeyMaterial"),
        leaks_private_key: dbg.contains("BEGIN PRIVATE KEY"),
        leaks_public_key: dbg.contains("BEGIN PUBLIC KEY"),
        contains_len_fields: dbg.contains("pkcs8_der_len") && dbg.contains("spki_der_len"),
    };
    insta::assert_yaml_snapshot!("keypair_material_debug_redaction", result);
}

#[test]
fn snapshot_kid_metadata() {
    let m = sample_material();
    let kid = m.kid();

    #[derive(Serialize)]
    struct KidMeta {
        kid_len: usize,
        is_base64url: bool,
        is_deterministic: bool,
    }

    let result = KidMeta {
        kid_len: kid.len(),
        is_base64url: kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        is_deterministic: m.kid() == kid,
    };
    insta::assert_yaml_snapshot!("keypair_material_kid", result);
}

#[test]
fn snapshot_truncation_behavior() {
    let m = sample_material();

    #[derive(Serialize)]
    struct TruncationShape {
        original_der_len: usize,
        requested_len: usize,
        result_len: usize,
    }

    let lengths = [0, 1, 2, 4, 10];
    let results: Vec<TruncationShape> = lengths
        .iter()
        .map(|&req| {
            let truncated = m.private_key_pkcs8_der_truncated(req);
            TruncationShape {
                original_der_len: m.private_key_pkcs8_der().len(),
                requested_len: req,
                result_len: truncated.len(),
            }
        })
        .collect();
    insta::assert_yaml_snapshot!("keypair_material_truncation", results);
}

#[test]
fn snapshot_corrupt_pem_shape() {
    use uselesskey_core::negative::CorruptPem;

    let m = sample_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

    #[derive(Serialize)]
    struct CorruptPemShape {
        variant: &'static str,
        original_pem_len: usize,
        corrupted_pem_len: usize,
        differs_from_original: bool,
    }

    let result = CorruptPemShape {
        variant: "BadHeader",
        original_pem_len: m.private_key_pkcs8_pem().len(),
        corrupted_pem_len: corrupted.len(),
        differs_from_original: corrupted != m.private_key_pkcs8_pem(),
    };
    insta::assert_yaml_snapshot!("keypair_material_corrupt_pem", result);
}

#[test]
fn snapshot_deterministic_corruption_stability() {
    let m = sample_material();

    #[derive(Serialize)]
    struct DeterministicShape {
        variant: &'static str,
        pem_is_deterministic: bool,
        pem_differs_from_original: bool,
        der_is_deterministic: bool,
        der_differs_from_original: bool,
    }

    let pem_a = m.private_key_pkcs8_pem_corrupt_deterministic("snapshot:v1");
    let pem_b = m.private_key_pkcs8_pem_corrupt_deterministic("snapshot:v1");
    let der_a = m.private_key_pkcs8_der_corrupt_deterministic("snapshot:v1");
    let der_b = m.private_key_pkcs8_der_corrupt_deterministic("snapshot:v1");

    let result = DeterministicShape {
        variant: "snapshot:v1",
        pem_is_deterministic: pem_a == pem_b,
        pem_differs_from_original: pem_a != m.private_key_pkcs8_pem(),
        der_is_deterministic: der_a == der_b,
        der_differs_from_original: der_a != m.private_key_pkcs8_der(),
    };
    insta::assert_yaml_snapshot!("keypair_material_deterministic_corruption", result);
}

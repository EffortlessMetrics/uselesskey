//! Insta snapshot tests for uselesskey-core-keypair.
//!
//! Snapshot keypair metadata shapes — field lengths, kid format, Debug safety.
//! All secret material is redacted.

use serde::Serialize;
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
mod fixtures;

fn sample() -> Pkcs8SpkiKeyMaterial {
    fixtures::rsa_material("snapshot-sample")
}

#[test]
fn snapshot_keypair_metadata() {
    #[derive(Serialize)]
    struct KeypairMetadata {
        pkcs8_der_len: usize,
        pkcs8_pem_len: usize,
        spki_der_len: usize,
        spki_pem_len: usize,
        kid_len: usize,
        kid_is_base64url_charset: bool,
    }

    let m = sample();
    let kid = m.kid();

    let result = KeypairMetadata {
        pkcs8_der_len: m.private_key_pkcs8_der().len(),
        pkcs8_pem_len: m.private_key_pkcs8_pem().len(),
        spki_der_len: m.public_key_spki_der().len(),
        spki_pem_len: m.public_key_spki_pem().len(),
        kid_len: kid.len(),
        kid_is_base64url_charset: kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
    };

    insta::assert_yaml_snapshot!("keypair_metadata", result);
}

#[test]
fn snapshot_keypair_debug_safety() {
    #[derive(Serialize)]
    struct DebugSafety {
        contains_struct_name: bool,
        contains_pkcs8_der_len: bool,
        contains_spki_der_len: bool,
        leaks_private_pem_header: bool,
        leaks_public_pem_header: bool,
        leaks_pem_body: bool,
        uses_non_exhaustive: bool,
    }

    let m = sample();
    let dbg = format!("{m:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("Pkcs8SpkiKeyMaterial"),
        contains_pkcs8_der_len: dbg.contains("pkcs8_der_len"),
        contains_spki_der_len: dbg.contains("spki_der_len"),
        leaks_private_pem_header: dbg.contains("BEGIN PRIVATE KEY"),
        leaks_public_pem_header: dbg.contains("BEGIN PUBLIC KEY"),
        leaks_pem_body: dbg.contains("BEGIN PRIVATE KEY") || dbg.contains("BEGIN PUBLIC KEY"),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("keypair_debug_safety", result);
}

#[test]
fn snapshot_keypair_kid_determinism() {
    #[derive(Serialize)]
    struct KidDeterminism {
        same_material_matches: bool,
        different_spki_differs: bool,
        same_spki_different_pkcs8_matches: bool,
    }

    let m1 = sample();
    let m2 = fixtures::rsa_material("snapshot-other");
    // Same SPKI, different PKCS#8
    let m3 = Pkcs8SpkiKeyMaterial::new(
        vec![0x01, 0x02],
        "other-private-pem",
        m1.public_key_spki_der().to_vec(),
        m1.public_key_spki_pem().to_owned(),
    );

    let result = KidDeterminism {
        same_material_matches: m1.kid() == m1.kid(),
        different_spki_differs: m1.kid() != m2.kid(),
        same_spki_different_pkcs8_matches: m1.kid() == m3.kid(),
    };

    insta::assert_yaml_snapshot!("keypair_kid_determinism", result);
}

#[test]
fn snapshot_keypair_negative_fixtures() {
    use uselesskey_core_negative::CorruptPem;

    #[derive(Serialize)]
    struct NegativeFixtures {
        bad_header_contains_corrupted: bool,
        bad_header_lacks_original: bool,
        bad_footer_contains_corrupted: bool,
        truncate_respects_length: bool,
        deterministic_pem_is_stable: bool,
        deterministic_der_is_stable: bool,
        different_variants_diverge: bool,
    }

    let m = sample();

    let bad_header = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    let bad_footer = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    let truncated = m.private_key_pkcs8_der_truncated(2);
    let det_a = m.private_key_pkcs8_pem_corrupt_deterministic("v1");
    let det_b = m.private_key_pkcs8_pem_corrupt_deterministic("v1");
    let det_c = m.private_key_pkcs8_pem_corrupt_deterministic("v2");
    let der_a = m.private_key_pkcs8_der_corrupt_deterministic("d1");
    let der_b = m.private_key_pkcs8_der_corrupt_deterministic("d1");

    let result = NegativeFixtures {
        bad_header_contains_corrupted: bad_header.contains("CORRUPTED KEY"),
        bad_header_lacks_original: !bad_header.contains("BEGIN PRIVATE KEY"),
        bad_footer_contains_corrupted: bad_footer.contains("END CORRUPTED KEY"),
        truncate_respects_length: truncated.len() == 2,
        deterministic_pem_is_stable: det_a == det_b,
        deterministic_der_is_stable: der_a == der_b,
        different_variants_diverge: det_a != det_c,
    };

    insta::assert_yaml_snapshot!("keypair_negative_fixtures", result);
}

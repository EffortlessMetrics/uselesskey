//! Insta snapshot tests for uselesskey-core-hmac-spec.
//!
//! Snapshot spec Display/Debug output and algorithm metadata.

use serde::Serialize;
use uselesskey_core_hmac_spec::HmacSpec;

#[derive(Serialize)]
struct HmacSpecSnapshot {
    variant: &'static str,
    alg_name: &'static str,
    byte_len: usize,
    debug_repr: String,
    stable_bytes: [u8; 4],
}

#[test]
fn snapshot_hmac_spec_all_variants() {
    let specs = [
        ("Hs256", HmacSpec::hs256()),
        ("Hs384", HmacSpec::hs384()),
        ("Hs512", HmacSpec::hs512()),
    ];

    let results: Vec<HmacSpecSnapshot> = specs
        .iter()
        .map(|(name, spec)| HmacSpecSnapshot {
            variant: name,
            alg_name: spec.alg_name(),
            byte_len: spec.byte_len(),
            debug_repr: format!("{:?}", spec),
            stable_bytes: spec.stable_bytes(),
        })
        .collect();

    insta::assert_yaml_snapshot!("hmac_spec_all_variants", results);
}

#[test]
fn snapshot_hmac_spec_stable_bytes_uniqueness() {
    #[derive(Serialize)]
    struct StableBytesCheck {
        hs256: [u8; 4],
        hs384: [u8; 4],
        hs512: [u8; 4],
        all_unique: bool,
    }

    let hs256 = HmacSpec::hs256().stable_bytes();
    let hs384 = HmacSpec::hs384().stable_bytes();
    let hs512 = HmacSpec::hs512().stable_bytes();

    let result = StableBytesCheck {
        hs256,
        hs384,
        hs512,
        all_unique: hs256 != hs384 && hs256 != hs512 && hs384 != hs512,
    };

    insta::assert_yaml_snapshot!("hmac_spec_stable_bytes", result);
}

#![forbid(unsafe_code)]

use uselesskey_core_hmac_spec::HmacSpec;

// ---------------------------------------------------------------------------
// Constructor helpers
// ---------------------------------------------------------------------------

#[test]
fn hs256_constructor() {
    let spec = HmacSpec::hs256();
    assert_eq!(spec, HmacSpec::Hs256);
}

#[test]
fn hs384_constructor() {
    let spec = HmacSpec::hs384();
    assert_eq!(spec, HmacSpec::Hs384);
}

#[test]
fn hs512_constructor() {
    let spec = HmacSpec::hs512();
    assert_eq!(spec, HmacSpec::Hs512);
}

// ---------------------------------------------------------------------------
// alg_name
// ---------------------------------------------------------------------------

#[test]
fn alg_name_matches_jose_standard() {
    assert_eq!(HmacSpec::Hs256.alg_name(), "HS256");
    assert_eq!(HmacSpec::Hs384.alg_name(), "HS384");
    assert_eq!(HmacSpec::Hs512.alg_name(), "HS512");
}

// ---------------------------------------------------------------------------
// byte_len
// ---------------------------------------------------------------------------

#[test]
fn byte_len_matches_hash_output_size() {
    assert_eq!(HmacSpec::Hs256.byte_len(), 32);
    assert_eq!(HmacSpec::Hs384.byte_len(), 48);
    assert_eq!(HmacSpec::Hs512.byte_len(), 64);
}

// ---------------------------------------------------------------------------
// stable_bytes — uniqueness and known values
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_are_distinct_across_variants() {
    let all = [
        HmacSpec::Hs256.stable_bytes(),
        HmacSpec::Hs384.stable_bytes(),
        HmacSpec::Hs512.stable_bytes(),
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "variants {i} and {j} collide");
            }
        }
    }
}

#[test]
fn stable_bytes_known_values() {
    assert_eq!(HmacSpec::Hs256.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(HmacSpec::Hs384.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(HmacSpec::Hs512.stable_bytes(), [0, 0, 0, 3]);
}

// ---------------------------------------------------------------------------
// Trait impls: Clone, Copy, Debug, Eq, PartialEq, Hash
// ---------------------------------------------------------------------------

#[test]
fn clone_and_copy() {
    let spec = HmacSpec::Hs256;
    #[allow(clippy::clone_on_copy)]
    let cloned = spec.clone();
    let copied = spec;
    assert_eq!(spec, cloned);
    assert_eq!(spec, copied);
}

#[test]
fn debug_impl_does_not_leak_key_material() {
    let dbg = format!("{:?}", HmacSpec::Hs256);
    assert!(dbg.contains("Hs256"), "Debug output: {dbg}");
    // Ensure no PEM/DER-shaped content
    assert!(
        !dbg.contains("BEGIN"),
        "Debug must not contain key material"
    );
}

#[test]
fn hash_impl_is_consistent() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(HmacSpec::Hs256);
    set.insert(HmacSpec::Hs384);
    set.insert(HmacSpec::Hs512);
    assert_eq!(set.len(), 3);

    // Re-inserting same variant does not grow the set
    set.insert(HmacSpec::Hs256);
    assert_eq!(set.len(), 3);
}

#[test]
fn equality_between_variants() {
    assert_eq!(HmacSpec::Hs256, HmacSpec::Hs256);
    assert_ne!(HmacSpec::Hs256, HmacSpec::Hs384);
    assert_ne!(HmacSpec::Hs256, HmacSpec::Hs512);
    assert_ne!(HmacSpec::Hs384, HmacSpec::Hs512);
}

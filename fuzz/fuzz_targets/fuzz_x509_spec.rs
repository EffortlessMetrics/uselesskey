#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

#[derive(Arbitrary, Debug)]
struct X509SpecInput {
    subject_cn: String,
    issuer_cn: String,
    validity_days: u32,
    not_before_days: u32,
    not_before_is_future: bool,
    is_ca: bool,
    rsa_bits_idx: u8,
    key_cert_sign: bool,
    crl_sign: bool,
    digital_signature: bool,
    key_encipherment: bool,
    sans: Vec<String>,
    chain_leaf_cn: String,
}

fuzz_target!(|input: X509SpecInput| {
    // Cap string lengths to avoid excessive allocations.
    if input.subject_cn.len() > 256
        || input.issuer_cn.len() > 256
        || input.chain_leaf_cn.len() > 256
        || input.sans.iter().any(|s| s.len() > 256)
        || input.sans.len() > 32
    {
        return;
    }

    let not_before = if input.not_before_is_future {
        NotBeforeOffset::DaysFromNow(input.not_before_days)
    } else {
        NotBeforeOffset::DaysAgo(input.not_before_days)
    };

    let key_usage = KeyUsage {
        key_cert_sign: input.key_cert_sign,
        crl_sign: input.crl_sign,
        digital_signature: input.digital_signature,
        key_encipherment: input.key_encipherment,
    };

    let rsa_bits = match input.rsa_bits_idx % 3 {
        0 => 2048,
        1 => 3072,
        _ => 4096,
    };

    // Builder chain must not panic.
    let spec = X509Spec::self_signed(&input.subject_cn)
        .with_validity_days(input.validity_days)
        .with_not_before(not_before)
        .with_rsa_bits(rsa_bits)
        .with_key_usage(key_usage)
        .with_is_ca(input.is_ca)
        .with_sans(input.sans.clone());

    // stable_bytes must be deterministic.
    let bytes1 = spec.stable_bytes();
    let bytes2 = spec.stable_bytes();
    assert_eq!(bytes1, bytes2, "stable_bytes must be deterministic");

    // CA spec must not panic.
    if !input.subject_cn.is_empty() {
        let ca = X509Spec::self_signed_ca(&input.subject_cn);
        assert!(ca.is_ca);
        assert!(ca.key_usage.key_cert_sign);
        let _ = ca.stable_bytes();
    }

    // Duration computations must not panic.
    let _ = spec.not_before_duration();
    let _ = spec.not_after_duration();

    // KeyUsage stable_bytes must be deterministic.
    assert_eq!(key_usage.stable_bytes(), key_usage.stable_bytes());

    // Exercise ChainSpec construction.
    if !input.chain_leaf_cn.is_empty() {
        let chain = ChainSpec::new(&input.chain_leaf_cn)
            .with_sans(input.sans)
            .with_rsa_bits(rsa_bits)
            .with_root_validity_days(input.validity_days)
            .with_intermediate_validity_days(input.validity_days)
            .with_leaf_validity_days(input.validity_days);

        let chain_bytes1 = chain.stable_bytes();
        let chain_bytes2 = chain.stable_bytes();
        assert_eq!(chain_bytes1, chain_bytes2, "ChainSpec stable_bytes must be deterministic");
    }
});

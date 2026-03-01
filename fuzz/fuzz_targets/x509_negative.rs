#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

/// Build an ASCII-safe label from fuzz bytes.
fn ascii_label(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "fuzz-default".to_string();
    }
    bytes
        .iter()
        .take(32)
        .map(|b| (b'a' + (b % 26)) as char)
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }

    let host = ascii_label(&data[2..]);

    // Build X509Spec with fuzz-driven parameters.
    let validity_days = u32::from(data[2]) * 10 + 1; // 1..2551
    let rsa_bits = match data[3] % 3 {
        0 => 1024,
        1 => 2048,
        _ => 4096,
    };
    let not_before = if data[4] % 2 == 0 {
        NotBeforeOffset::DaysAgo(u32::from(data[4]))
    } else {
        NotBeforeOffset::DaysFromNow(u32::from(data[4]))
    };
    let key_usage = if data[5] % 2 == 0 {
        KeyUsage::leaf()
    } else {
        KeyUsage::ca()
    };

    let spec = X509Spec::self_signed(&host)
        .with_validity_days(validity_days)
        .with_rsa_bits(rsa_bits)
        .with_not_before(not_before)
        .with_key_usage(key_usage)
        .with_is_ca(data[5] % 4 == 0)
        .with_sans(vec![host.clone(), format!("*.{host}")]);

    // Apply every X509Negative variant and verify panic-freedom.
    let x509_variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for variant in &x509_variants {
        let modified = variant.apply_to_spec(&spec);
        // Verify the variant name is non-empty.
        assert!(!variant.variant_name().is_empty());
        assert!(!variant.description().is_empty());
        // Double-apply: ensure idempotent application doesn't panic.
        let _ = variant.apply_to_spec(&modified);
    }

    // Build ChainSpec with fuzz-driven parameters.
    let chain = ChainSpec::new(&host)
        .with_sans(vec![host.clone()])
        .with_root_cn(&format!("Root-{host}"))
        .with_intermediate_cn(&format!("Inter-{host}"))
        .with_rsa_bits(rsa_bits)
        .with_root_validity_days(validity_days * 2)
        .with_intermediate_validity_days(validity_days)
        .with_leaf_validity_days(validity_days / 2 + 1);

    // Apply every ChainNegative variant.
    let chain_variants: Vec<ChainNegative> = vec![
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
        ChainNegative::HostnameMismatch {
            wrong_hostname: format!("wrong.{host}"),
        },
    ];

    for variant in &chain_variants {
        let modified = variant.apply_to_spec(&chain);
        assert!(!variant.variant_name().is_empty());
        // Double-apply.
        let _ = variant.apply_to_spec(&modified);
    }

    // Also test self_signed_ca path.
    let ca_spec = X509Spec::self_signed_ca(&host)
        .with_validity_days(validity_days)
        .with_rsa_bits(rsa_bits);

    for variant in &x509_variants {
        let _ = variant.apply_to_spec(&ca_spec);
    }
});

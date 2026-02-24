#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, X509Spec};

fn ascii_label(input: &[u8]) -> String {
    if input.is_empty() {
        return "default".to_string();
    }

    let mut out = String::new();
    for byte in input.iter().copied() {
        out.push((b'a' + (byte % 26)) as char);
    }
    if out.is_empty() {
        "default".to_string()
    } else {
        out
    }
}

fuzz_target!(|data: &[u8]| {
    let host = ascii_label(&data);
    let spec = X509Spec::self_signed(&host);
    let chain = ChainSpec::new(&host);

    let x509_variant = match data.first().copied().unwrap_or(0) % 4 {
        0 => X509Negative::Expired,
        1 => X509Negative::NotYetValid,
        2 => X509Negative::WrongKeyUsage,
        _ => X509Negative::SelfSignedButClaimsCA,
    };

    let chain_variant = if data.len() < 2 {
        ChainNegative::UnknownCa
    } else {
        match data[1] % 5 {
            0 => ChainNegative::UnknownCa,
            1 => ChainNegative::ExpiredLeaf,
            2 => ChainNegative::ExpiredIntermediate,
            3 => ChainNegative::RevokedLeaf,
            _ => ChainNegative::HostnameMismatch {
                wrong_hostname: format!("{}.{}", host, host),
            },
        }
    };

    let x509_first = x509_variant.apply_to_spec(&spec);
    let x509_second = x509_variant.apply_to_spec(&spec);
    assert_eq!(x509_first, x509_second);
    assert!(!x509_variant.variant_name().is_empty());

    let chain_first = chain_variant.apply_to_spec(&chain);
    let chain_second = chain_variant.apply_to_spec(&chain);
    assert_eq!(chain_first, chain_second);
    assert!(!chain_variant.variant_name().is_empty());
});

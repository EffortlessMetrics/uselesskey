#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

fn ascii_label(input: &[u8]) -> String {
    if input.is_empty() {
        return "default".to_string();
    }
    input.iter().map(|b| (b'a' + (b % 26)) as char).collect()
}

fuzz_target!(|data: &[u8]| {
    let cn = ascii_label(data);

    // Self-signed spec with builder chain driven by fuzz data.
    let mut spec = X509Spec::self_signed(&cn);
    if data.len() >= 4 {
        let days = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        spec = spec.with_validity_days(days.max(1));
    }
    if data.len() >= 5 {
        let offset = if data[4] % 2 == 0 {
            NotBeforeOffset::DaysAgo(data[4] as u32)
        } else {
            NotBeforeOffset::DaysFromNow(data[4] as u32)
        };
        spec = spec.with_not_before(offset);
    }
    if data.len() >= 6 {
        let bits = match data[5] % 3 {
            0 => 2048,
            1 => 3072,
            _ => 4096,
        };
        spec = spec.with_rsa_bits(bits);
    }
    if data.len() >= 7 {
        let usage = KeyUsage {
            key_cert_sign: data[6] & 1 != 0,
            crl_sign: data[6] & 2 != 0,
            digital_signature: data[6] & 4 != 0,
            key_encipherment: data[6] & 8 != 0,
        };
        spec = spec.with_key_usage(usage);
    }
    spec = spec.with_is_ca(data.first().copied().unwrap_or(0) % 2 == 0);

    if data.len() >= 8 {
        let sans: Vec<String> = data[8..]
            .chunks(4)
            .map(|c| ascii_label(c))
            .collect();
        spec = spec.with_sans(sans);
    }

    // stable_bytes must be deterministic.
    let bytes1 = spec.stable_bytes();
    let bytes2 = spec.stable_bytes();
    assert_eq!(bytes1, bytes2);
    assert!(!bytes1.is_empty());

    // CA variant.
    let ca_spec = X509Spec::self_signed_ca(&cn);
    let ca_bytes = ca_spec.stable_bytes();
    assert!(!ca_bytes.is_empty());

    // ChainSpec with builder chain.
    let mut chain = ChainSpec::new(&cn);
    if data.len() >= 2 {
        chain = chain.with_root_cn(ascii_label(&data[..2]));
    }
    if data.len() >= 3 {
        chain = chain.with_intermediate_cn(ascii_label(&data[..3]));
    }
    if data.len() >= 4 {
        chain = chain.with_rsa_bits(2048);
    }

    let chain_bytes1 = chain.stable_bytes();
    let chain_bytes2 = chain.stable_bytes();
    assert_eq!(chain_bytes1, chain_bytes2);
    assert!(!chain_bytes1.is_empty());
});

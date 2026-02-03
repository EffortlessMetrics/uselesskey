#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rsa::pkcs8::DecodePrivateKey;

use uselesskey::{Factory, RsaFactoryExt, RsaSpec};
use uselesskey::negative::{corrupt_pem, CorruptPem};

static GOOD_PEM: OnceLock<String> = OnceLock::new();

fn good_pem() -> &'static str {
    GOOD_PEM
        .get_or_init(|| {
            // One-time RSA keygen; fuzz iterations mutate/parse only.
            let fx = Factory::deterministic(uselesskey::Seed::new([7u8; 32]));
            let rsa = fx.rsa("fuzz", RsaSpec::rs256());
            rsa.private_key_pkcs8_pem().to_string()
        })
        .as_str()
}

fuzz_target!(|data: &[u8]| {
    let pem = good_pem();

    // Choose corruption based on the first byte.
    let how = match data.get(0).copied().unwrap_or(0) % 5 {
        0 => CorruptPem::BadHeader,
        1 => CorruptPem::BadFooter,
        2 => CorruptPem::BadBase64,
        3 => CorruptPem::ExtraBlankLine,
        _ => CorruptPem::Truncate { bytes: (data.len() % 64) },
    };

    let bad = corrupt_pem(pem, how);

    // We don't care if it parses; we care that parsing doesn't UB/panic.
    let _ = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
});

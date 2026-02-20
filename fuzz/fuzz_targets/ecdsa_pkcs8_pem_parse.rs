#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use p256::pkcs8::DecodePrivateKey;

use uselesskey::negative::{corrupt_pem, CorruptPem};
use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Factory, Seed};

static GOOD_PEM: OnceLock<String> = OnceLock::new();

fn good_pem() -> &'static str {
    GOOD_PEM
        .get_or_init(|| {
            let fx = Factory::deterministic(Seed::new([7u8; 32]));
            let ec = fx.ecdsa("fuzz", EcdsaSpec::es256());
            ec.private_key_pkcs8_pem().to_string()
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
        _ => CorruptPem::Truncate {
            bytes: (data.len() % 64),
        },
    };

    let bad = corrupt_pem(pem, how);

    // We don't care if it parses; we care that parsing doesn't UB/panic.
    let _ = p256::SecretKey::from_pkcs8_pem(&bad);
});

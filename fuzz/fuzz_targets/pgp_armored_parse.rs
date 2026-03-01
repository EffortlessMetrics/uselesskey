#![no_main]

use std::io::Cursor;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

use uselesskey::negative::{corrupt_pem, CorruptPem};
use uselesskey::{Factory, PgpFactoryExt, PgpSpec, Seed};

static GOOD_PRIVATE: OnceLock<String> = OnceLock::new();
static GOOD_PUBLIC: OnceLock<String> = OnceLock::new();

fn good_private() -> &'static str {
    GOOD_PRIVATE
        .get_or_init(|| {
            let fx = Factory::deterministic(Seed::new([7u8; 32]));
            let pgp = fx.pgp("fuzz", PgpSpec::ed25519());
            pgp.private_key_armored().to_string()
        })
        .as_str()
}

fn good_public() -> &'static str {
    GOOD_PUBLIC
        .get_or_init(|| {
            let fx = Factory::deterministic(Seed::new([7u8; 32]));
            let pgp = fx.pgp("fuzz", PgpSpec::ed25519());
            pgp.public_key_armored().to_string()
        })
        .as_str()
}

fuzz_target!(|data: &[u8]| {
    // Use the first byte to select which armor to corrupt and how.
    let selector = data.get(0).copied().unwrap_or(0);
    let armor = if selector % 2 == 0 {
        good_private()
    } else {
        good_public()
    };

    let how = match (selector / 2) % 5 {
        0 => CorruptPem::BadHeader,
        1 => CorruptPem::BadFooter,
        2 => CorruptPem::BadBase64,
        3 => CorruptPem::ExtraBlankLine,
        _ => CorruptPem::Truncate {
            bytes: (data.len() % 64),
        },
    };

    let bad = corrupt_pem(armor, how);

    // We don't care if it parses; we care that parsing doesn't UB/panic.
    let _ = SignedSecretKey::from_armor_single(Cursor::new(&bad));
    let _ = SignedPublicKey::from_armor_single(Cursor::new(&bad));
});

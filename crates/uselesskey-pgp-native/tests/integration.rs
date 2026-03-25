use uselesskey_core::Factory;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};
use pgp::types::KeyDetails;
use uselesskey_pgp_native::PgpNativeExt;

#[test]
fn integration_parses_armored_vs_binary() {
    let fx = Factory::random();
    let keypair = fx.pgp("interop", PgpSpec::ed25519());

    let binary_secret = keypair.secret_key();
    let armor_secret = keypair.secret_key_armor();

    let binary_public = keypair.public_key();
    let armor_public = keypair.public_key_armor();

    assert_eq!(binary_secret.fingerprint().to_string(), armor_secret.fingerprint().to_string());
    assert_eq!(binary_public.fingerprint().to_string(), armor_public.fingerprint().to_string());
    assert_eq!(keypair.fingerprint(), binary_secret.fingerprint().to_string());
    assert_eq!(keypair.fingerprint(), binary_public.fingerprint().to_string());
}

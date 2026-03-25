use pgp::types::KeyDetails;
use uselesskey_core::Factory;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};
use uselesskey_pgp_native::PgpNativeExt;

fn main() {
    let fx = Factory::random();
    let keypair = fx.pgp("example", PgpSpec::rsa_3072());

    let secret = keypair.secret_key_armor();
    let public = keypair.public_key_armor();

    println!("fingerprint: {}", secret.fingerprint());
    println!(
        "public key matches: {}",
        secret.fingerprint() == public.fingerprint()
    );
}

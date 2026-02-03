use cucumber::{given, then, when, World};
use uselesskey::{Factory, RsaFactoryExt, RsaSpec};

#[derive(Debug, Default, World)]
struct UselessWorld {
    factory: Option<Factory>,
    label: Option<String>,
    pkcs8_pem_1: Option<String>,
    pkcs8_pem_2: Option<String>,
    spki_der_good: Option<Vec<u8>>,
}

#[given(regex = r#"^a deterministic factory seeded with "([^"]+)"$"#)]
fn deterministic_factory(world: &mut UselessWorld, seed: String) {
    // In the BDD harness we intentionally treat the seed as an env-style value.
    // This matches the normal "seed via CI env var" workflow.
    let seed = uselesskey::Seed::from_env_value(&seed).expect("seed parse");
    world.factory = Some(Factory::deterministic(seed));
}

#[given("a random factory")]
fn random_factory(world: &mut UselessWorld) {
    world.factory = Some(Factory::random());
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)"$"#)]
fn gen_rsa(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());

    world.label = Some(label);
    world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_good = Some(rsa.public_key_spki_der().to_vec());
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" again$"#)]
fn gen_rsa_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
}

#[then("the PKCS8 PEM should be identical")]
fn pem_should_match(world: &mut UselessWorld) {
    assert_eq!(world.pkcs8_pem_1.as_deref(), world.pkcs8_pem_2.as_deref());
}

#[then("a mismatched SPKI DER should parse and differ")]
fn mismatched_spki_should_parse_and_differ(world: &mut UselessWorld) {
    let fx = world.factory.as_ref().expect("factory not set");
    let label = world.label.as_ref().expect("label not set");

    let rsa = fx.rsa(label, RsaSpec::rs256());
    let mismatch = rsa.mismatched_public_key_spki_der();

    let good = world.spki_der_good.as_ref().expect("good spki missing");

    // Parse both and compare modulus (extremely likely to differ).
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let good_pub = rsa::RsaPublicKey::from_public_key_der(good).unwrap();
    let mismatch_pub = rsa::RsaPublicKey::from_public_key_der(&mismatch).unwrap();

    assert_ne!(good_pub.n(), mismatch_pub.n());
}

/// Cucumber entry point.
///
/// We deliberately run from a `[[test]]` target with `harness = false` so
/// Cucumber controls output formatting.
#[tokio::main]
async fn main() {
    UselessWorld::run("features").await;
}

use cucumber::{given, then, when, World};
use uselesskey::negative::CorruptPem;
use uselesskey::{Factory, RsaFactoryExt, RsaKeyPair, RsaSpec};

fn set_public_kid(jwk: &mut uselesskey::jwk::PublicJwk, kid: &str) {
    use uselesskey::jwk::PublicJwk;
    match jwk {
        PublicJwk::Rsa(j) => j.kid = kid.to_string(),
        PublicJwk::Ec(j) => j.kid = kid.to_string(),
        PublicJwk::Okp(j) => j.kid = kid.to_string(),
    }
}

fn set_private_kid(jwk: &mut uselesskey::jwk::PrivateJwk, kid: &str) {
    use uselesskey::jwk::PrivateJwk;
    match jwk {
        PrivateJwk::Rsa(j) => j.kid = kid.to_string(),
        PrivateJwk::Ec(j) => j.kid = kid.to_string(),
        PrivateJwk::Okp(j) => j.kid = kid.to_string(),
        PrivateJwk::Oct(j) => j.kid = kid.to_string(),
    }
}

#[derive(Default, Debug, World)]
struct UselessWorld {
    factory: Option<Factory>,
    rsa: Option<RsaKeyPair>,
    label: Option<String>,

    // For comparing two generations of the same key.
    pkcs8_pem_1: Option<String>,
    pkcs8_pem_2: Option<String>,

    // For comparing two different keys.
    spki_der_1: Option<Vec<u8>>,
    spki_der_2: Option<Vec<u8>>,

    // Original DER for truncation tests.
    pkcs8_der_original: Option<Vec<u8>>,

    // Mismatched key storage.
    mismatch_1: Option<Vec<u8>>,
    mismatch_2: Option<Vec<u8>>,

    // Corrupted artifacts.
    corrupted_pem: Option<String>,
    truncated_der: Option<Vec<u8>>,

    // Tempfile handles.
    private_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    public_tempfile: Option<uselesskey_core::sink::TempArtifact>,

    // JWK storage.
    kid_1: Option<String>,
    kid_2: Option<String>,
}

// =============================================================================
// Given steps
// =============================================================================

#[given(regex = r#"^a deterministic factory seeded with "([^"]+)"$"#)]
fn deterministic_factory(world: &mut UselessWorld, seed: String) {
    let seed = uselesskey::Seed::from_env_value(&seed).expect("seed parse");
    world.factory = Some(Factory::deterministic(seed));
}

#[given("a random factory")]
fn random_factory(world: &mut UselessWorld) {
    world.factory = Some(Factory::random());
}

#[given(regex = r#"^I generate an RSA key for label "([^"]+)"$"#)]
fn given_gen_rsa(world: &mut UselessWorld, label: String) {
    gen_rsa(world, label);
}

// =============================================================================
// When steps
// =============================================================================

#[when(regex = r#"^I generate an RSA key for label "([^"]+)"$"#)]
fn gen_rsa(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());

    world.label = Some(label);
    world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.pkcs8_der_original = Some(rsa.private_key_pkcs8_der().to_vec());
    world.spki_der_1 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" again$"#)]
fn gen_rsa_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate another RSA key for label "([^"]+)"$"#)]
fn gen_rsa_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when("I clear the factory cache")]
fn clear_cache(world: &mut UselessWorld) {
    world
        .factory
        .as_ref()
        .expect("factory not set")
        .clear_cache();
}

#[when(regex = r#"^I switch to a deterministic factory seeded with "([^"]+)"$"#)]
fn switch_factory(world: &mut UselessWorld, seed: String) {
    let seed = uselesskey::Seed::from_env_value(&seed).expect("seed parse");
    world.factory = Some(Factory::deterministic(seed));
}

#[when("I get the mismatched public key")]
fn get_mismatch(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.mismatch_1 = Some(rsa.mismatched_public_key_spki_der());
}

#[when("I get the mismatched public key again")]
fn get_mismatch_again(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.mismatch_2 = Some(rsa.mismatched_public_key_spki_der());
}

// --- Corruption steps ---

#[when("I corrupt the PKCS8 PEM with BadHeader")]
fn corrupt_bad_header(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.corrupted_pem = Some(rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader));
}

#[when("I corrupt the PKCS8 PEM with BadFooter")]
fn corrupt_bad_footer(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.corrupted_pem = Some(rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter));
}

#[when("I corrupt the PKCS8 PEM with BadBase64")]
fn corrupt_bad_base64(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.corrupted_pem = Some(rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64));
}

#[when(regex = r"^I corrupt the PKCS8 PEM with Truncate to (\d+) bytes$")]
fn corrupt_truncate(world: &mut UselessWorld, bytes: usize) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.corrupted_pem = Some(rsa.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes }));
}

#[when("I corrupt the PKCS8 PEM with ExtraBlankLine")]
fn corrupt_extra_blank(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.corrupted_pem = Some(rsa.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine));
}

#[when(regex = r"^I truncate the PKCS8 DER to (\d+) bytes$")]
fn truncate_der(world: &mut UselessWorld, len: usize) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.truncated_der = Some(rsa.private_key_pkcs8_der_truncated(len));
}

// --- Tempfile steps ---

#[when("I write the private key to a tempfile")]
fn write_private_tempfile(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.private_tempfile = Some(rsa.write_private_key_pkcs8_pem().expect("write failed"));
}

#[when("I write the public key to a tempfile")]
fn write_public_tempfile(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.public_tempfile = Some(rsa.write_public_key_spki_pem().expect("write failed"));
}

// --- JWK steps ---

#[when("I capture the kid")]
fn capture_kid(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.kid_1 = Some(rsa.kid());
}

#[when("I capture the kid again")]
fn capture_kid_again(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.kid_2 = Some(rsa.kid());
}

// =============================================================================
// Then steps
// =============================================================================

#[then("the PKCS8 PEM should be identical")]
fn pem_should_match(world: &mut UselessWorld) {
    assert_eq!(world.pkcs8_pem_1.as_deref(), world.pkcs8_pem_2.as_deref());
}

#[then("the keys should have different moduli")]
fn keys_differ(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let der1 = world.spki_der_1.as_ref().expect("spki_der_1 not set");
    let der2 = world.spki_der_2.as_ref().expect("spki_der_2 not set");

    let pub1 = rsa::RsaPublicKey::from_public_key_der(der1).unwrap();
    let pub2 = rsa::RsaPublicKey::from_public_key_der(der2).unwrap();

    assert_ne!(pub1.n(), pub2.n(), "moduli should differ");
}

#[then("a mismatched SPKI DER should parse and differ")]
fn mismatched_spki_should_parse_and_differ(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    let mismatch = rsa.mismatched_public_key_spki_der();
    let good = world.spki_der_1.as_ref().expect("good spki missing");

    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let good_pub = rsa::RsaPublicKey::from_public_key_der(good).unwrap();
    let mismatch_pub = rsa::RsaPublicKey::from_public_key_der(&mismatch).unwrap();

    assert_ne!(good_pub.n(), mismatch_pub.n());
}

#[then("the mismatched keys should be identical")]
fn mismatch_identical(world: &mut UselessWorld) {
    assert_eq!(world.mismatch_1, world.mismatch_2);
}

#[then("the PKCS8 DER should be parseable")]
fn pkcs8_der_parseable(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let der = world
        .pkcs8_der_original
        .as_ref()
        .expect("pkcs8_der not set");
    rsa::RsaPrivateKey::from_pkcs8_der(der).expect("PKCS8 DER should parse");
}

#[then("the SPKI PEM should be parseable")]
fn spki_pem_parseable(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePublicKey;

    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let pem = rsa_key.public_key_spki_pem();
    rsa::RsaPublicKey::from_public_key_pem(pem).expect("SPKI PEM should parse");
}

#[then("the SPKI DER should be parseable")]
fn spki_der_parseable(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePublicKey;

    let der = world.spki_der_1.as_ref().expect("spki_der not set");
    rsa::RsaPublicKey::from_public_key_der(der).expect("SPKI DER should parse");
}

// --- Corruption assertions ---

#[then(regex = r#"^the corrupted PEM should contain "([^"]+)"$"#)]
fn corrupted_pem_contains(world: &mut UselessWorld, needle: String) {
    let pem = world.corrupted_pem.as_ref().expect("corrupted_pem not set");
    assert!(pem.contains(&needle), "expected PEM to contain '{needle}'");
}

#[then(regex = r"^the corrupted PEM should have length (\d+)$")]
fn corrupted_pem_length(world: &mut UselessWorld, expected: usize) {
    let pem = world.corrupted_pem.as_ref().expect("corrupted_pem not set");
    assert_eq!(pem.len(), expected);
}

#[then("the corrupted PEM should fail to parse")]
fn corrupted_pem_fails(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let pem = world.corrupted_pem.as_ref().expect("corrupted_pem not set");
    let result = rsa::RsaPrivateKey::from_pkcs8_pem(pem);
    assert!(result.is_err(), "corrupted PEM should fail to parse");
}

#[then(regex = r"^the truncated DER should have length (\d+)$")]
fn truncated_der_length(world: &mut UselessWorld, expected: usize) {
    let der = world.truncated_der.as_ref().expect("truncated_der not set");
    assert_eq!(der.len(), expected);
}

#[then("the truncated DER should fail to parse")]
fn truncated_der_fails(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let der = world.truncated_der.as_ref().expect("truncated_der not set");
    let result = rsa::RsaPrivateKey::from_pkcs8_der(der);
    assert!(result.is_err(), "truncated DER should fail to parse");
}

#[then("the truncated DER should equal the original")]
fn truncated_der_equals_original(world: &mut UselessWorld) {
    let truncated = world.truncated_der.as_ref().expect("truncated_der not set");
    let original = world
        .pkcs8_der_original
        .as_ref()
        .expect("pkcs8_der not set");
    assert_eq!(truncated, original);
}

// --- Tempfile assertions ---

#[then(regex = r#"^the tempfile path should end with "([^"]+)"$"#)]
fn tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let path = if let Some(tf) = &world.private_tempfile {
        tf.path().to_string_lossy().to_string()
    } else if let Some(tf) = &world.public_tempfile {
        tf.path().to_string_lossy().to_string()
    } else {
        panic!("no tempfile set");
    };
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then("reading the tempfile should match the private key PEM")]
fn tempfile_matches_private(world: &mut UselessWorld) {
    let tf = world
        .private_tempfile
        .as_ref()
        .expect("private_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    assert_eq!(contents, rsa_key.private_key_pkcs8_pem());
}

#[then("reading the tempfile should match the public key PEM")]
fn tempfile_matches_public(world: &mut UselessWorld) {
    let tf = world
        .public_tempfile
        .as_ref()
        .expect("public_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    assert_eq!(contents, rsa_key.public_key_spki_pem());
}

// --- JWK assertions ---

#[then(regex = r#"^the public JWK should have kty "([^"]+)"$"#)]
fn jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the public JWK should have alg "([^"]+)"$"#)]
fn jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the public JWK should have use "([^"]+)"$"#)]
fn jwk_has_use(world: &mut UselessWorld, expected: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the public JWK should have a kid")]
fn jwk_has_kid(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk();
    assert!(jwk["kid"].is_string(), "kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "kid should not be empty"
    );
}

#[then("the public JWK should have n and e parameters")]
fn jwk_has_n_and_e(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk();
    assert!(jwk["n"].is_string(), "n should be present");
    assert!(jwk["e"].is_string(), "e should be present");
    assert!(
        !jwk["n"].as_str().unwrap().is_empty(),
        "n should not be empty"
    );
    assert!(
        !jwk["e"].as_str().unwrap().is_empty(),
        "e should not be empty"
    );
}

#[then("the JWKS should have a keys array")]
fn jwks_has_keys(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwks = rsa_key.public_jwks();
    assert!(jwks["keys"].is_array(), "keys should be an array");
}

#[then("the JWKS keys array should contain one key")]
fn jwks_has_one_key(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwks = rsa_key.public_jwks();
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 1);
}

#[then("the kids should be identical")]
fn kids_identical(world: &mut UselessWorld) {
    assert_eq!(world.kid_1, world.kid_2);
}

#[then("the kids should differ")]
fn kids_differ(world: &mut UselessWorld) {
    assert_ne!(world.kid_1, world.kid_2);
}

/// Cucumber entry point.
///
/// We deliberately run from a `[[test]]` target with `harness = false` so
/// Cucumber controls output formatting.
#[tokio::main]
async fn main() {
    UselessWorld::run("features").await;
}

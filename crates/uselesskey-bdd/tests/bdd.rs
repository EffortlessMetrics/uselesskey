use cucumber::{given, then, when, World};
use uselesskey::negative::CorruptPem;
use uselesskey::{
    EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec, Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec,
    Factory, RsaFactoryExt, RsaKeyPair, RsaSpec, X509Cert, X509FactoryExt, X509Spec,
};

#[derive(Debug, Default, World)]
struct UselessWorld {
    factory: Option<Factory>,
    rsa: Option<RsaKeyPair>,
    ed25519: Option<Ed25519KeyPair>,
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

    // Ed25519-specific storage
    ed25519_pkcs8_pem_1: Option<String>,
    ed25519_pkcs8_pem_2: Option<String>,
    ed25519_spki_der_1: Option<Vec<u8>>,
    ed25519_spki_der_2: Option<Vec<u8>>,
    ed25519_pkcs8_der_original: Option<Vec<u8>>,
    ed25519_mismatch_1: Option<Vec<u8>>,
    ed25519_mismatch_2: Option<Vec<u8>>,
    ed25519_corrupted_pem: Option<String>,
    ed25519_truncated_der: Option<Vec<u8>>,
    ed25519_kid_1: Option<String>,
    ed25519_kid_2: Option<String>,

    // ECDSA-specific storage
    ecdsa: Option<EcdsaKeyPair>,
    ecdsa_pkcs8_pem_1: Option<String>,
    ecdsa_pkcs8_pem_2: Option<String>,
    ecdsa_spki_der_1: Option<Vec<u8>>,
    ecdsa_spki_der_2: Option<Vec<u8>>,
    ecdsa_pkcs8_der_original: Option<Vec<u8>>,
    ecdsa_mismatch_1: Option<Vec<u8>>,
    ecdsa_mismatch_2: Option<Vec<u8>>,
    ecdsa_corrupted_pem: Option<String>,
    ecdsa_truncated_der: Option<Vec<u8>>,
    ecdsa_kid_1: Option<String>,
    ecdsa_kid_2: Option<String>,

    // X.509-specific storage
    x509: Option<X509Cert>,
    x509_cert_pem_1: Option<String>,
    x509_cert_pem_2: Option<String>,
    x509_cert_der_1: Option<Vec<u8>>,
    x509_cert_der_2: Option<Vec<u8>>,
    x509_private_key_pem_1: Option<String>,
    x509_private_key_pem_2: Option<String>,
    x509_expired: Option<X509Cert>,
    x509_not_yet_valid: Option<X509Cert>,
    x509_corrupted_pem: Option<String>,
    x509_truncated_der: Option<Vec<u8>>,
    x509_cert_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_key_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_chain_tempfile: Option<uselesskey_core::sink::TempArtifact>,
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

// =============================================================================
// Ed25519 When steps
// =============================================================================

#[when(regex = r#"^I generate an Ed25519 key for label "([^"]+)"$"#)]
fn gen_ed25519(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ed25519 = fx.ed25519(&label, Ed25519Spec::new());

    world.label = Some(label);
    world.ed25519_pkcs8_pem_1 = Some(ed25519.private_key_pkcs8_pem().to_string());
    world.ed25519_pkcs8_der_original = Some(ed25519.private_key_pkcs8_der().to_vec());
    world.ed25519_spki_der_1 = Some(ed25519.public_key_spki_der().to_vec());
    world.ed25519 = Some(ed25519);
}

#[when(regex = r#"^I generate an Ed25519 key for label "([^"]+)" again$"#)]
fn gen_ed25519_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ed25519 = fx.ed25519(&label, Ed25519Spec::new());
    world.ed25519_pkcs8_pem_2 = Some(ed25519.private_key_pkcs8_pem().to_string());
    world.ed25519_spki_der_2 = Some(ed25519.public_key_spki_der().to_vec());
    world.ed25519 = Some(ed25519);
}

#[when(regex = r#"^I generate another Ed25519 key for label "([^"]+)"$"#)]
fn gen_ed25519_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ed25519 = fx.ed25519(&label, Ed25519Spec::new());
    world.ed25519_pkcs8_pem_2 = Some(ed25519.private_key_pkcs8_pem().to_string());
    world.ed25519_spki_der_2 = Some(ed25519.public_key_spki_der().to_vec());
    world.ed25519 = Some(ed25519);
}

#[when("I get the mismatched Ed25519 public key")]
fn get_ed25519_mismatch(world: &mut UselessWorld) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_mismatch_1 = Some(ed25519.mismatched_public_key_spki_der());
}

#[when("I get the mismatched Ed25519 public key again")]
fn get_ed25519_mismatch_again(world: &mut UselessWorld) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_mismatch_2 = Some(ed25519.mismatched_public_key_spki_der());
}

#[when("I corrupt the Ed25519 PKCS8 PEM with BadHeader")]
fn corrupt_ed25519_bad_header(world: &mut UselessWorld) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_corrupted_pem =
        Some(ed25519.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader));
}

#[when(regex = r"^I truncate the Ed25519 PKCS8 DER to (\d+) bytes$")]
fn truncate_ed25519_der(world: &mut UselessWorld, len: usize) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_truncated_der = Some(ed25519.private_key_pkcs8_der_truncated(len));
}

#[when("I capture the Ed25519 kid")]
fn capture_ed25519_kid(world: &mut UselessWorld) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_kid_1 = Some(ed25519.kid());
}

#[when("I capture the Ed25519 kid again")]
fn capture_ed25519_kid_again(world: &mut UselessWorld) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.ed25519_kid_2 = Some(ed25519.kid());
}

// =============================================================================
// Ed25519 Then steps
// =============================================================================

#[then("the Ed25519 PKCS8 PEM should be identical")]
fn ed25519_pem_should_match(world: &mut UselessWorld) {
    assert_eq!(
        world.ed25519_pkcs8_pem_1.as_deref(),
        world.ed25519_pkcs8_pem_2.as_deref()
    );
}

#[then("the Ed25519 keys should have different public keys")]
fn ed25519_keys_differ(world: &mut UselessWorld) {
    let der1 = world
        .ed25519_spki_der_1
        .as_ref()
        .expect("ed25519_spki_der_1 not set");
    let der2 = world
        .ed25519_spki_der_2
        .as_ref()
        .expect("ed25519_spki_der_2 not set");
    assert_ne!(der1, der2, "Ed25519 public keys should differ");
}

#[then("an Ed25519 mismatched SPKI DER should parse and differ")]
fn ed25519_mismatched_spki_should_parse_and_differ(world: &mut UselessWorld) {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::VerifyingKey;

    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    let mismatch = ed25519.mismatched_public_key_spki_der();
    let good = world
        .ed25519_spki_der_1
        .as_ref()
        .expect("good ed25519 spki missing");

    let good_pub = VerifyingKey::from_public_key_der(good).unwrap();
    let mismatch_pub = VerifyingKey::from_public_key_der(&mismatch).unwrap();

    assert_ne!(good_pub.as_bytes(), mismatch_pub.as_bytes());
}

#[then("the mismatched Ed25519 keys should be identical")]
fn ed25519_mismatch_identical(world: &mut UselessWorld) {
    assert_eq!(world.ed25519_mismatch_1, world.ed25519_mismatch_2);
}

#[then("the Ed25519 PKCS8 DER should be parseable")]
fn ed25519_pkcs8_der_parseable(world: &mut UselessWorld) {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ed25519_dalek::SigningKey;

    let der = world
        .ed25519_pkcs8_der_original
        .as_ref()
        .expect("ed25519_pkcs8_der not set");
    SigningKey::from_pkcs8_der(der).expect("Ed25519 PKCS8 DER should parse");
}

#[then("the Ed25519 SPKI PEM should be parseable")]
fn ed25519_spki_pem_parseable(world: &mut UselessWorld) {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::VerifyingKey;

    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let pem = ed25519_key.public_key_spki_pem();
    VerifyingKey::from_public_key_pem(pem).expect("Ed25519 SPKI PEM should parse");
}

#[then("the Ed25519 SPKI DER should be parseable")]
fn ed25519_spki_der_parseable(world: &mut UselessWorld) {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    use ed25519_dalek::VerifyingKey;

    let der = world
        .ed25519_spki_der_1
        .as_ref()
        .expect("ed25519_spki_der not set");
    VerifyingKey::from_public_key_der(der).expect("Ed25519 SPKI DER should parse");
}

#[then(regex = r#"^the corrupted Ed25519 PEM should contain "([^"]+)"$"#)]
fn ed25519_corrupted_pem_contains(world: &mut UselessWorld, needle: String) {
    let pem = world
        .ed25519_corrupted_pem
        .as_ref()
        .expect("ed25519_corrupted_pem not set");
    assert!(
        pem.contains(&needle),
        "expected Ed25519 PEM to contain '{needle}'"
    );
}

#[then(regex = r"^the truncated Ed25519 DER should have length (\d+)$")]
fn ed25519_truncated_der_length(world: &mut UselessWorld, expected: usize) {
    let der = world
        .ed25519_truncated_der
        .as_ref()
        .expect("ed25519_truncated_der not set");
    assert_eq!(der.len(), expected);
}

#[then("the truncated Ed25519 DER should fail to parse")]
fn ed25519_truncated_der_fails(world: &mut UselessWorld) {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ed25519_dalek::SigningKey;

    let der = world
        .ed25519_truncated_der
        .as_ref()
        .expect("ed25519_truncated_der not set");
    let result = SigningKey::from_pkcs8_der(der);
    assert!(
        result.is_err(),
        "truncated Ed25519 DER should fail to parse"
    );
}

#[then(regex = r#"^the Ed25519 public JWK should have kty "([^"]+)"$"#)]
fn ed25519_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have crv "([^"]+)"$"#)]
fn ed25519_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have alg "([^"]+)"$"#)]
fn ed25519_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have use "([^"]+)"$"#)]
fn ed25519_jwk_has_use(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the Ed25519 public JWK should have a kid")]
fn ed25519_jwk_has_kid(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert!(jwk["kid"].is_string(), "Ed25519 kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "Ed25519 kid should not be empty"
    );
}

#[then("the Ed25519 public JWK should have x parameter")]
fn ed25519_jwk_has_x(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk();
    assert!(jwk["x"].is_string(), "Ed25519 x should be present");
    assert!(
        !jwk["x"].as_str().unwrap().is_empty(),
        "Ed25519 x should not be empty"
    );
}

#[then("the Ed25519 JWKS should have a keys array")]
fn ed25519_jwks_has_keys(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwks = ed25519_key.public_jwks();
    assert!(jwks["keys"].is_array(), "Ed25519 keys should be an array");
}

#[then("the Ed25519 JWKS keys array should contain one key")]
fn ed25519_jwks_has_one_key(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwks = ed25519_key.public_jwks();
    let keys = jwks["keys"]
        .as_array()
        .expect("Ed25519 keys should be array");
    assert_eq!(keys.len(), 1);
}

#[then("the Ed25519 kids should be identical")]
fn ed25519_kids_identical(world: &mut UselessWorld) {
    assert_eq!(world.ed25519_kid_1, world.ed25519_kid_2);
}

// =============================================================================
// ECDSA When steps
// =============================================================================

#[when(regex = r#"^I generate an ECDSA ES256 key for label "([^"]+)"$"#)]
fn gen_ecdsa_es256(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es256());

    world.label = Some(label);
    world.ecdsa_pkcs8_pem_1 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_pkcs8_der_original = Some(ecdsa.private_key_pkcs8_der().to_vec());
    world.ecdsa_spki_der_1 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when(regex = r#"^I generate an ECDSA ES256 key for label "([^"]+)" again$"#)]
fn gen_ecdsa_es256_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es256());
    world.ecdsa_pkcs8_pem_2 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_spki_der_2 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when(regex = r#"^I generate another ECDSA ES256 key for label "([^"]+)"$"#)]
fn gen_ecdsa_es256_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es256());
    world.ecdsa_pkcs8_pem_2 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_spki_der_2 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when(regex = r#"^I generate an ECDSA ES384 key for label "([^"]+)"$"#)]
fn gen_ecdsa_es384(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es384());

    world.label = Some(label);
    world.ecdsa_pkcs8_pem_1 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_pkcs8_der_original = Some(ecdsa.private_key_pkcs8_der().to_vec());
    world.ecdsa_spki_der_1 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when(regex = r#"^I generate an ECDSA ES384 key for label "([^"]+)" again$"#)]
fn gen_ecdsa_es384_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es384());
    world.ecdsa_pkcs8_pem_2 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_spki_der_2 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when(regex = r#"^I generate another ECDSA ES384 key for label "([^"]+)"$"#)]
fn gen_ecdsa_es384_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let ecdsa = fx.ecdsa(&label, EcdsaSpec::es384());
    world.ecdsa_pkcs8_pem_2 = Some(ecdsa.private_key_pkcs8_pem().to_string());
    world.ecdsa_spki_der_2 = Some(ecdsa.public_key_spki_der().to_vec());
    world.ecdsa = Some(ecdsa);
}

#[when("I get the mismatched ECDSA public key")]
fn get_ecdsa_mismatch(world: &mut UselessWorld) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_mismatch_1 = Some(ecdsa.mismatched_public_key_spki_der());
}

#[when("I get the mismatched ECDSA public key again")]
fn get_ecdsa_mismatch_again(world: &mut UselessWorld) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_mismatch_2 = Some(ecdsa.mismatched_public_key_spki_der());
}

#[when("I corrupt the ECDSA PKCS8 PEM with BadHeader")]
fn corrupt_ecdsa_bad_header(world: &mut UselessWorld) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_corrupted_pem = Some(ecdsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader));
}

#[when(regex = r"^I truncate the ECDSA PKCS8 DER to (\d+) bytes$")]
fn truncate_ecdsa_der(world: &mut UselessWorld, len: usize) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_truncated_der = Some(ecdsa.private_key_pkcs8_der_truncated(len));
}

#[when("I capture the ECDSA kid")]
fn capture_ecdsa_kid(world: &mut UselessWorld) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_kid_1 = Some(ecdsa.kid());
}

#[when("I capture the ECDSA kid again")]
fn capture_ecdsa_kid_again(world: &mut UselessWorld) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.ecdsa_kid_2 = Some(ecdsa.kid());
}

// =============================================================================
// ECDSA Then steps
// =============================================================================

#[then("the ECDSA PKCS8 PEM should be identical")]
fn ecdsa_pem_should_match(world: &mut UselessWorld) {
    assert_eq!(
        world.ecdsa_pkcs8_pem_1.as_deref(),
        world.ecdsa_pkcs8_pem_2.as_deref()
    );
}

#[then("the ECDSA keys should have different public keys")]
fn ecdsa_keys_differ(world: &mut UselessWorld) {
    let der1 = world
        .ecdsa_spki_der_1
        .as_ref()
        .expect("ecdsa_spki_der_1 not set");
    let der2 = world
        .ecdsa_spki_der_2
        .as_ref()
        .expect("ecdsa_spki_der_2 not set");
    assert_ne!(der1, der2, "ECDSA public keys should differ");
}

#[then("an ECDSA mismatched SPKI DER should parse and differ")]
fn ecdsa_mismatched_spki_should_parse_and_differ(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePublicKey as _;

    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    let mismatch = ecdsa.mismatched_public_key_spki_der();
    let good = world
        .ecdsa_spki_der_1
        .as_ref()
        .expect("good ecdsa spki missing");

    // Try to parse as P-256 first, then P-384
    let (good_bytes, mismatch_bytes) =
        if let Ok(good_pub) = p256::PublicKey::from_public_key_der(good) {
            let mismatch_pub =
                p256::PublicKey::from_public_key_der(&mismatch).expect("mismatch should parse");
            (
                good_pub.to_sec1_bytes().to_vec(),
                mismatch_pub.to_sec1_bytes().to_vec(),
            )
        } else {
            let good_pub =
                p384::PublicKey::from_public_key_der(good).expect("should parse as P-384");
            let mismatch_pub =
                p384::PublicKey::from_public_key_der(&mismatch).expect("mismatch should parse");
            (
                good_pub.to_sec1_bytes().to_vec(),
                mismatch_pub.to_sec1_bytes().to_vec(),
            )
        };

    assert_ne!(good_bytes, mismatch_bytes);
}

#[then("the mismatched ECDSA keys should be identical")]
fn ecdsa_mismatch_identical(world: &mut UselessWorld) {
    assert_eq!(world.ecdsa_mismatch_1, world.ecdsa_mismatch_2);
}

#[then("the ECDSA PKCS8 DER should be parseable")]
fn ecdsa_pkcs8_der_parseable(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePrivateKey as _;

    let der = world
        .ecdsa_pkcs8_der_original
        .as_ref()
        .expect("ecdsa_pkcs8_der not set");

    // Try P-256 first, then P-384
    let parsed = p256::SecretKey::from_pkcs8_der(der)
        .map(|_| ())
        .or_else(|_| p384::SecretKey::from_pkcs8_der(der).map(|_| ()));

    parsed.expect("ECDSA PKCS8 DER should parse");
}

#[then("the ECDSA SPKI PEM should be parseable")]
fn ecdsa_spki_pem_parseable(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePublicKey as _;

    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let pem = ecdsa_key.public_key_spki_pem();

    // Try P-256 first, then P-384
    let parsed = p256::PublicKey::from_public_key_pem(pem)
        .map(|_| ())
        .or_else(|_| p384::PublicKey::from_public_key_pem(pem).map(|_| ()));

    parsed.expect("ECDSA SPKI PEM should parse");
}

#[then("the ECDSA SPKI DER should be parseable")]
fn ecdsa_spki_der_parseable(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePublicKey as _;

    let der = world
        .ecdsa_spki_der_1
        .as_ref()
        .expect("ecdsa_spki_der not set");

    // Try P-256 first, then P-384
    let parsed = p256::PublicKey::from_public_key_der(der)
        .map(|_| ())
        .or_else(|_| p384::PublicKey::from_public_key_der(der).map(|_| ()));

    parsed.expect("ECDSA SPKI DER should parse");
}

#[then(regex = r#"^the corrupted ECDSA PEM should contain "([^"]+)"$"#)]
fn ecdsa_corrupted_pem_contains(world: &mut UselessWorld, needle: String) {
    let pem = world
        .ecdsa_corrupted_pem
        .as_ref()
        .expect("ecdsa_corrupted_pem not set");
    assert!(
        pem.contains(&needle),
        "expected ECDSA PEM to contain '{needle}'"
    );
}

#[then(regex = r"^the truncated ECDSA DER should have length (\d+)$")]
fn ecdsa_truncated_der_length(world: &mut UselessWorld, expected: usize) {
    let der = world
        .ecdsa_truncated_der
        .as_ref()
        .expect("ecdsa_truncated_der not set");
    assert_eq!(der.len(), expected);
}

#[then("the truncated ECDSA DER should fail to parse")]
fn ecdsa_truncated_der_fails(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePrivateKey as _;

    let der = world
        .ecdsa_truncated_der
        .as_ref()
        .expect("ecdsa_truncated_der not set");

    let p256_result = p256::SecretKey::from_pkcs8_der(der);
    let p384_result = p384::SecretKey::from_pkcs8_der(der);

    assert!(
        p256_result.is_err() && p384_result.is_err(),
        "truncated ECDSA DER should fail to parse"
    );
}

#[then(regex = r#"^the ECDSA public JWK should have kty "([^"]+)"$"#)]
fn ecdsa_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have crv "([^"]+)"$"#)]
fn ecdsa_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have alg "([^"]+)"$"#)]
fn ecdsa_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have use "([^"]+)"$"#)]
fn ecdsa_jwk_has_use(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the ECDSA public JWK should have a kid")]
fn ecdsa_jwk_has_kid(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert!(jwk["kid"].is_string(), "ECDSA kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "ECDSA kid should not be empty"
    );
}

#[then("the ECDSA public JWK should have x and y parameters")]
fn ecdsa_jwk_has_x_y(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk();
    assert!(jwk["x"].is_string(), "ECDSA x should be present");
    assert!(jwk["y"].is_string(), "ECDSA y should be present");
    assert!(
        !jwk["x"].as_str().unwrap().is_empty(),
        "ECDSA x should not be empty"
    );
    assert!(
        !jwk["y"].as_str().unwrap().is_empty(),
        "ECDSA y should not be empty"
    );
}

#[then("the ECDSA JWKS should have a keys array")]
fn ecdsa_jwks_has_keys(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwks = ecdsa_key.public_jwks();
    assert!(jwks["keys"].is_array(), "ECDSA keys should be an array");
}

#[then("the ECDSA JWKS keys array should contain one key")]
fn ecdsa_jwks_has_one_key(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwks = ecdsa_key.public_jwks();
    let keys = jwks["keys"]
        .as_array()
        .expect("ECDSA keys should be array");
    assert_eq!(keys.len(), 1);
}

#[then("the ECDSA kids should be identical")]
fn ecdsa_kids_identical(world: &mut UselessWorld) {
    assert_eq!(world.ecdsa_kid_1, world.ecdsa_kid_2);
}

// =============================================================================
// X.509 When steps
// =============================================================================

#[when(regex = r#"^I generate an X\.509 certificate for domain "([^"]+)" with label "([^"]+)"$"#)]
fn gen_x509(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = X509Spec::self_signed(&domain);
    let x509 = fx.x509_self_signed(&label, spec);

    world.label = Some(label);
    world.x509_cert_pem_1 = Some(x509.cert_pem().to_string());
    world.x509_cert_der_1 = Some(x509.cert_der().to_vec());
    world.x509_private_key_pem_1 = Some(x509.private_key_pkcs8_pem().to_string());
    world.x509 = Some(x509);
}

#[when(
    regex = r#"^I generate an X\.509 certificate for domain "([^"]+)" with label "([^"]+)" again$"#
)]
fn gen_x509_again(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = X509Spec::self_signed(&domain);
    let x509 = fx.x509_self_signed(&label, spec);

    world.x509_cert_pem_2 = Some(x509.cert_pem().to_string());
    world.x509_cert_der_2 = Some(x509.cert_der().to_vec());
    world.x509_private_key_pem_2 = Some(x509.private_key_pkcs8_pem().to_string());
    world.x509 = Some(x509);
}

#[when(
    regex = r#"^I generate another X\.509 certificate for domain "([^"]+)" with label "([^"]+)"$"#
)]
fn gen_x509_second(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = X509Spec::self_signed(&domain);
    let x509 = fx.x509_self_signed(&label, spec);

    world.x509_cert_pem_2 = Some(x509.cert_pem().to_string());
    world.x509_cert_der_2 = Some(x509.cert_der().to_vec());
    world.x509 = Some(x509);
}

#[when("I get the expired variant of the X.509 certificate")]
fn get_x509_expired(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let expired = x509.expired();
    world.x509_cert_der_2 = Some(expired.cert_der().to_vec());
    world.x509_expired = Some(expired);
}

#[when("I get the not-yet-valid variant of the X.509 certificate")]
fn get_x509_not_yet_valid(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let not_yet_valid = x509.not_yet_valid();
    world.x509_cert_der_2 = Some(not_yet_valid.cert_der().to_vec());
    world.x509_not_yet_valid = Some(not_yet_valid);
}

#[when("I corrupt the X.509 certificate PEM with BadHeader")]
fn corrupt_x509_bad_header(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_corrupted_pem = Some(x509.corrupt_cert_pem(CorruptPem::BadHeader));
}

#[when(regex = r"^I truncate the X\.509 certificate DER to (\d+) bytes$")]
fn truncate_x509_der(world: &mut UselessWorld, len: usize) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_truncated_der = Some(x509.truncate_cert_der(len));
}

#[when("I write the X.509 certificate PEM to a tempfile")]
fn write_x509_cert_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_cert_tempfile = Some(x509.write_cert_pem().expect("write failed"));
}

#[when("I write the X.509 private key PEM to a tempfile")]
fn write_x509_key_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_key_tempfile = Some(x509.write_private_key_pem().expect("write failed"));
}

#[when("I write the X.509 chain PEM to a tempfile")]
fn write_x509_chain_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_chain_tempfile = Some(x509.write_chain_pem().expect("write failed"));
}

// =============================================================================
// X.509 Then steps
// =============================================================================

#[then("the X.509 certificate PEM should be identical")]
fn x509_pem_should_match(world: &mut UselessWorld) {
    assert_eq!(
        world.x509_cert_pem_1.as_deref(),
        world.x509_cert_pem_2.as_deref()
    );
}

#[then("the X.509 private key should be identical")]
fn x509_private_key_should_match(world: &mut UselessWorld) {
    assert_eq!(
        world.x509_private_key_pem_1.as_deref(),
        world.x509_private_key_pem_2.as_deref()
    );
}

#[then("the X.509 certificates should have different DER")]
fn x509_certs_differ(world: &mut UselessWorld) {
    let der1 = world
        .x509_cert_der_1
        .as_ref()
        .expect("x509_cert_der_1 not set");
    let der2 = world
        .x509_cert_der_2
        .as_ref()
        .expect("x509_cert_der_2 not set");
    assert_ne!(der1, der2, "X.509 certificates should differ");
}

#[then(regex = r#"^the X\.509 certificate PEM should contain "([^"]+)"$"#)]
fn x509_cert_pem_contains(world: &mut UselessWorld, needle: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let pem = x509.cert_pem();
    assert!(
        pem.contains(&needle),
        "expected X.509 cert PEM to contain '{needle}'"
    );
}

#[then("the X.509 certificate PEM should be parseable")]
fn x509_cert_pem_parseable(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let der = x509.cert_der();
    x509_parser::parse_x509_certificate(der).expect("X.509 cert should parse");
}

#[then("the X.509 certificate DER should be parseable")]
fn x509_cert_der_parseable(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let der = x509.cert_der();
    x509_parser::parse_x509_certificate(der).expect("X.509 cert DER should parse");
}

#[then(regex = r#"^the X\.509 private key PEM should contain "([^"]+)"$"#)]
fn x509_key_pem_contains(world: &mut UselessWorld, needle: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let pem = x509.private_key_pkcs8_pem();
    assert!(
        pem.contains(&needle),
        "expected X.509 key PEM to contain '{needle}'"
    );
}

#[then(regex = r#"^the X\.509 chain PEM should contain "([^"]+)"$"#)]
fn x509_chain_pem_contains(world: &mut UselessWorld, needle: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let chain = x509.chain_pem();
    assert!(
        chain.contains(&needle),
        "expected X.509 chain PEM to contain '{needle}'"
    );
}

#[then(regex = r#"^the X\.509 certificate should have common name "([^"]+)"$"#)]
fn x509_has_common_name(world: &mut UselessWorld, expected_cn: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let der = x509.cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("should have CN")
        .as_str()
        .expect("CN should be string");

    assert_eq!(cn, expected_cn);
}

#[then("the expired X.509 certificate should be parseable")]
fn x509_expired_parseable(world: &mut UselessWorld) {
    let expired = world.x509_expired.as_ref().expect("expired cert not set");
    let der = expired.cert_der();
    x509_parser::parse_x509_certificate(der).expect("expired cert should parse");
}

#[then("the expired X.509 certificate should have not_after in the past")]
fn x509_expired_not_after_past(world: &mut UselessWorld) {
    use x509_parser::time::ASN1Time;

    let expired = world.x509_expired.as_ref().expect("expired cert not set");
    let der = expired.cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");

    let not_after = cert.validity().not_after;
    let now = ASN1Time::now();

    assert!(
        not_after < now,
        "expired cert should have not_after in the past"
    );
}

#[then("the not-yet-valid X.509 certificate should be parseable")]
fn x509_not_yet_valid_parseable(world: &mut UselessWorld) {
    let nyv = world
        .x509_not_yet_valid
        .as_ref()
        .expect("not_yet_valid cert not set");
    let der = nyv.cert_der();
    x509_parser::parse_x509_certificate(der).expect("not_yet_valid cert should parse");
}

#[then("the not-yet-valid X.509 certificate should have not_before in the future")]
fn x509_not_yet_valid_not_before_future(world: &mut UselessWorld) {
    use x509_parser::time::ASN1Time;

    let nyv = world
        .x509_not_yet_valid
        .as_ref()
        .expect("not_yet_valid cert not set");
    let der = nyv.cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");

    let not_before = cert.validity().not_before;
    let now = ASN1Time::now();

    assert!(
        not_before > now,
        "not_yet_valid cert should have not_before in the future"
    );
}

#[then(regex = r#"^the corrupted X\.509 PEM should contain "([^"]+)"$"#)]
fn x509_corrupted_pem_contains(world: &mut UselessWorld, needle: String) {
    let pem = world
        .x509_corrupted_pem
        .as_ref()
        .expect("x509_corrupted_pem not set");
    assert!(
        pem.contains(&needle),
        "expected corrupted X.509 PEM to contain '{needle}'"
    );
}

#[then(regex = r"^the truncated X\.509 DER should have length (\d+)$")]
fn x509_truncated_der_length(world: &mut UselessWorld, expected: usize) {
    let der = world
        .x509_truncated_der
        .as_ref()
        .expect("x509_truncated_der not set");
    assert_eq!(der.len(), expected);
}

#[then("the truncated X.509 DER should fail to parse")]
fn x509_truncated_der_fails(world: &mut UselessWorld) {
    let der = world
        .x509_truncated_der
        .as_ref()
        .expect("x509_truncated_der not set");
    let result = x509_parser::parse_x509_certificate(der);
    assert!(
        result.is_err(),
        "truncated X.509 DER should fail to parse"
    );
}

#[then(regex = r#"^the X\.509 tempfile path should end with "([^"]+)"$"#)]
fn x509_cert_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_cert_tempfile
        .as_ref()
        .expect("x509_cert_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the X\.509 key tempfile path should end with "([^"]+)"$"#)]
fn x509_key_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_key_tempfile
        .as_ref()
        .expect("x509_key_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the X\.509 chain tempfile path should end with "([^"]+)"$"#)]
fn x509_chain_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_chain_tempfile
        .as_ref()
        .expect("x509_chain_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then("reading the X.509 tempfile should match the certificate PEM")]
fn x509_tempfile_matches_cert(world: &mut UselessWorld) {
    let tf = world
        .x509_cert_tempfile
        .as_ref()
        .expect("x509_cert_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let x509 = world.x509.as_ref().expect("x509 not set");
    assert_eq!(contents, x509.cert_pem());
}

#[then("reading the X.509 key tempfile should match the private key PEM")]
fn x509_tempfile_matches_key(world: &mut UselessWorld) {
    let tf = world
        .x509_key_tempfile
        .as_ref()
        .expect("x509_key_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let x509 = world.x509.as_ref().expect("x509 not set");
    assert_eq!(contents, x509.private_key_pkcs8_pem());
}

/// Cucumber entry point.
///
/// We deliberately run from a `[[test]]` target with `harness = false` so
/// Cucumber controls output formatting.
#[tokio::main]
async fn main() {
    UselessWorld::run("features").await;
}

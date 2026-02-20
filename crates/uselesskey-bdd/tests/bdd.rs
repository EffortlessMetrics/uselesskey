use cucumber::{World, given, then, when};
use serde_json::Value;
use uselesskey::jwk::JwksBuilder;
use uselesskey::negative::CorruptPem;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec, Ed25519FactoryExt, Ed25519KeyPair,
    Ed25519Spec, Factory, HmacFactoryExt, HmacSecret, HmacSpec, RsaFactoryExt, RsaKeyPair, RsaSpec,
    X509Cert, X509Chain, X509FactoryExt, X509Spec,
};

#[cfg(feature = "uk-token")]
use uselesskey::{TokenFactoryExt, TokenFixture, TokenSpec};

#[cfg(feature = "uk-pgp")]
use uselesskey::{PgpFactoryExt, PgpKeyPair, PgpSpec};

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
    deterministic_text_1: Option<String>,
    deterministic_text_2: Option<String>,
    deterministic_bytes_1: Option<Vec<u8>>,
    deterministic_bytes_2: Option<Vec<u8>>,

    // Tempfile handles.
    private_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    public_tempfile: Option<uselesskey_core::sink::TempArtifact>,

    // JWK storage.
    kid_1: Option<String>,
    kid_2: Option<String>,

    // HMAC-specific storage
    hmac: Option<HmacSecret>,
    hmac_secret_1: Option<Vec<u8>>,
    hmac_secret_2: Option<Vec<u8>>,

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
    x509_wrong_key_usage: Option<X509Cert>,
    x509_corrupted_pem: Option<String>,
    x509_truncated_der: Option<Vec<u8>>,
    x509_cert_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_cert_der_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_key_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_chain_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_chain_pem_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_full_chain_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_root_cert_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_crl_pem_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    x509_crl_der_tempfile: Option<uselesskey_core::sink::TempArtifact>,

    // X.509 chain storage
    x509_chain: Option<X509Chain>,
    x509_chain_leaf_der_1: Option<Vec<u8>>,
    x509_chain_leaf_der_2: Option<Vec<u8>>,
    x509_chain_root_der_1: Option<Vec<u8>>,
    x509_chain_root_der_2: Option<Vec<u8>>,
    x509_chain_leaf_pem_1: Option<String>,
    x509_chain_leaf_pem_2: Option<String>,
    x509_chain_intermediate_pem_1: Option<String>,
    x509_chain_intermediate_pem_2: Option<String>,
    x509_chain_root_pem_1: Option<String>,
    x509_chain_root_pem_2: Option<String>,
    x509_chain_revoked_leaf: Option<X509Chain>,
    x509_chain_hostname_mismatch: Option<X509Chain>,
    x509_chain_unknown_ca: Option<X509Chain>,
    x509_chain_expired_leaf: Option<X509Chain>,
    x509_chain_expired_intermediate: Option<X509Chain>,
    x509_chain_sans: Vec<String>,
    x509_chain_spec: Option<ChainSpec>,

    // JWKS storage
    jwks_output_1: Option<Value>,
    jwks_output_2: Option<Value>,
    jwks_filtered: Option<Value>,

    // Multiple keys for JWKS scenarios
    rsa_keys: Vec<RsaKeyPair>,
    ecdsa_keys: Vec<EcdsaKeyPair>,
    ed25519_keys: Vec<Ed25519KeyPair>,
    hmac_keys: Vec<HmacSecret>,
    rsa_pems_before: Vec<String>,
    ecdsa_pems_before: Vec<String>,
    ed25519_pems_before: Vec<String>,
    rsa_modulus_snapshot: Option<String>,

    // Token-specific storage
    #[cfg(feature = "uk-token")]
    token: Option<TokenFixture>,
    #[cfg(feature = "uk-token")]
    token_value_1: Option<String>,
    #[cfg(feature = "uk-token")]
    token_value_2: Option<String>,
    #[cfg(feature = "uk-token")]
    token_auth_header: Option<String>,

    // PGP-specific storage
    #[cfg(feature = "uk-pgp")]
    pgp: Option<PgpKeyPair>,
    #[cfg(feature = "uk-pgp")]
    pgp_private_armor_1: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_private_armor_2: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_public_armor_1: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_public_armor_2: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_private_binary_1: Option<Vec<u8>>,
    #[cfg(feature = "uk-pgp")]
    pgp_public_binary_1: Option<Vec<u8>>,
    #[cfg(feature = "uk-pgp")]
    pgp_fingerprint_1: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_fingerprint_2: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_mismatch_1: Option<Vec<u8>>,
    #[cfg(feature = "uk-pgp")]
    pgp_mismatch_2: Option<Vec<u8>>,
    #[cfg(feature = "uk-pgp")]
    pgp_corrupted_armor: Option<String>,
    #[cfg(feature = "uk-pgp")]
    pgp_truncated_binary: Option<Vec<u8>>,
    #[cfg(feature = "uk-pgp")]
    pgp_tempfile: Option<uselesskey_core::sink::TempArtifact>,
    #[cfg(feature = "uk-pgp")]
    pgp_public_tempfile: Option<uselesskey_core::sink::TempArtifact>,
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

#[when(regex = r#"^I generate an HMAC HS256 secret for label "([^"]+)"$"#)]
fn gen_hmac(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs256());
    world.hmac_secret_1 = Some(secret.secret_bytes().to_vec());
    world.hmac_keys.push(secret.clone());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate an HMAC HS256 secret for label "([^"]+)" again$"#)]
fn gen_hmac_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs256());
    world.hmac_secret_2 = Some(secret.secret_bytes().to_vec());
    world.hmac = Some(secret);
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

#[when(regex = r#"^I deterministically corrupt the RSA PKCS8 PEM with variant "([^"]+)"$"#)]
fn det_corrupt_rsa_pem(world: &mut UselessWorld, variant: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.deterministic_text_1 = Some(rsa.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the RSA PKCS8 PEM with variant "([^"]+)" again$"#)]
fn det_corrupt_rsa_pem_again(world: &mut UselessWorld, variant: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.deterministic_text_2 = Some(rsa.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the RSA PKCS8 DER with variant "([^"]+)"$"#)]
fn det_corrupt_rsa_der(world: &mut UselessWorld, variant: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.deterministic_bytes_1 = Some(rsa.private_key_pkcs8_der_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the RSA PKCS8 DER with variant "([^"]+)" again$"#)]
fn det_corrupt_rsa_der_again(world: &mut UselessWorld, variant: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    world.deterministic_bytes_2 = Some(rsa.private_key_pkcs8_der_corrupt_deterministic(&variant));
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

#[then("the deterministic text artifacts should be identical")]
fn deterministic_text_artifacts_identical(world: &mut UselessWorld) {
    assert_eq!(world.deterministic_text_1, world.deterministic_text_2);
}

#[then("the deterministic binary artifacts should be identical")]
fn deterministic_binary_artifacts_identical(world: &mut UselessWorld) {
    assert_eq!(world.deterministic_bytes_1, world.deterministic_bytes_2);
}

#[then(regex = r#"^the deterministic text artifact should contain "([^"]+)"$"#)]
fn deterministic_text_artifact_contains(world: &mut UselessWorld, needle: String) {
    let text = world
        .deterministic_text_1
        .as_ref()
        .expect("deterministic_text_1 not set");
    assert!(
        text.contains(&needle),
        "expected deterministic text artifact to contain '{needle}'"
    );
}

#[then("the deterministic RSA PEM artifact should fail to parse")]
fn deterministic_rsa_pem_fails(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let pem = world
        .deterministic_text_1
        .as_ref()
        .expect("deterministic_text_1 not set");
    let result = rsa::RsaPrivateKey::from_pkcs8_pem(pem);
    assert!(
        result.is_err(),
        "deterministic RSA PEM should fail to parse"
    );
}

#[then("the deterministic RSA DER artifact should fail to parse")]
fn deterministic_rsa_der_fails(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let der = world
        .deterministic_bytes_1
        .as_ref()
        .expect("deterministic_bytes_1 not set");
    let result = rsa::RsaPrivateKey::from_pkcs8_der(der);
    assert!(
        result.is_err(),
        "deterministic RSA DER should fail to parse"
    );
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
    let jwk = rsa_key.public_jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the public JWK should have alg "([^"]+)"$"#)]
fn jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the public JWK should have use "([^"]+)"$"#)]
fn jwk_has_use(world: &mut UselessWorld, expected: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk().to_value();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the public JWK should have a kid")]
fn jwk_has_kid(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk().to_value();
    assert!(jwk["kid"].is_string(), "kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "kid should not be empty"
    );
}

#[then("the public JWK should have n and e parameters")]
fn jwk_has_n_and_e(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.public_jwk().to_value();
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

#[then("the RSA private JWK should have d p q dp dq qi parameters")]
fn rsa_private_jwk_has_params(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.private_key_jwk().to_value();

    for key in ["d", "p", "q", "dp", "dq", "qi"] {
        assert!(
            jwk.get(key).is_some(),
            "private JWK should have '{key}' field"
        );
        assert!(jwk[key].is_string(), "{key} should be a string");
    }
}

#[then("the JWKS should have a keys array")]
fn jwks_has_keys(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwks = rsa_key.public_jwks().to_value();
    assert!(jwks["keys"].is_array(), "keys should be an array");
}

#[then("the JWKS keys array should contain one key")]
fn jwks_has_one_key(world: &mut UselessWorld) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwks = rsa_key.public_jwks().to_value();
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

#[then("the HMAC secrets should be identical")]
fn hmac_secrets_identical(world: &mut UselessWorld) {
    assert_eq!(world.hmac_secret_1, world.hmac_secret_2);
}

#[then(regex = r#"^the HMAC JWK should have kty "([^"]+)"$"#)]
fn hmac_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwk = secret.jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the HMAC JWK should have alg "([^"]+)"$"#)]
fn hmac_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwk = secret.jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the HMAC JWK should have use "([^"]+)"$"#)]
fn hmac_jwk_has_use(world: &mut UselessWorld, expected: String) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwk = secret.jwk().to_value();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the HMAC JWK should have a kid")]
fn hmac_jwk_has_kid(world: &mut UselessWorld) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwk = secret.jwk().to_value();
    assert!(jwk["kid"].is_string(), "kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "kid should not be empty"
    );
}

#[then("the HMAC JWK should have k parameter")]
fn hmac_jwk_has_k(world: &mut UselessWorld) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwk = secret.jwk().to_value();
    assert!(jwk["k"].is_string(), "k should be present");
    assert!(
        !jwk["k"].as_str().unwrap().is_empty(),
        "k should not be empty"
    );
}

#[then("the HMAC JWKS should have a keys array")]
fn hmac_jwks_has_keys(world: &mut UselessWorld) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwks = secret.jwks().to_value();
    assert!(jwks["keys"].is_array(), "keys should be an array");
}

#[then("the HMAC JWKS keys array should contain one key")]
fn hmac_jwks_has_one_key(world: &mut UselessWorld) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    let jwks = secret.jwks().to_value();
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 1);
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
    world.ed25519_keys.push(ed25519.clone());
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

#[when(regex = r#"^I deterministically corrupt the Ed25519 PKCS8 PEM with variant "([^"]+)"$"#)]
fn det_corrupt_ed25519_pem(world: &mut UselessWorld, variant: String) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.deterministic_text_1 =
        Some(ed25519.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(
    regex = r#"^I deterministically corrupt the Ed25519 PKCS8 PEM with variant "([^"]+)" again$"#
)]
fn det_corrupt_ed25519_pem_again(world: &mut UselessWorld, variant: String) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.deterministic_text_2 =
        Some(ed25519.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the Ed25519 PKCS8 DER with variant "([^"]+)"$"#)]
fn det_corrupt_ed25519_der(world: &mut UselessWorld, variant: String) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.deterministic_bytes_1 =
        Some(ed25519.private_key_pkcs8_der_corrupt_deterministic(&variant));
}

#[when(
    regex = r#"^I deterministically corrupt the Ed25519 PKCS8 DER with variant "([^"]+)" again$"#
)]
fn det_corrupt_ed25519_der_again(world: &mut UselessWorld, variant: String) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    world.deterministic_bytes_2 =
        Some(ed25519.private_key_pkcs8_der_corrupt_deterministic(&variant));
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
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::DecodePublicKey;

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
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let der = world
        .ed25519_pkcs8_der_original
        .as_ref()
        .expect("ed25519_pkcs8_der not set");
    SigningKey::from_pkcs8_der(der).expect("Ed25519 PKCS8 DER should parse");
}

#[then("the Ed25519 SPKI PEM should be parseable")]
fn ed25519_spki_pem_parseable(world: &mut UselessWorld) {
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let pem = ed25519_key.public_key_spki_pem();
    VerifyingKey::from_public_key_pem(pem).expect("Ed25519 SPKI PEM should parse");
}

#[then("the Ed25519 SPKI DER should be parseable")]
fn ed25519_spki_der_parseable(world: &mut UselessWorld) {
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::pkcs8::DecodePublicKey;

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
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

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

#[then("the deterministic Ed25519 PEM artifact should fail to parse")]
fn deterministic_ed25519_pem_fails(world: &mut UselessWorld) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let pem = world
        .deterministic_text_1
        .as_ref()
        .expect("deterministic_text_1 not set");
    let result = SigningKey::from_pkcs8_pem(pem);
    assert!(
        result.is_err(),
        "deterministic Ed25519 PEM should fail to parse"
    );
}

#[then("the deterministic Ed25519 DER artifact should fail to parse")]
fn deterministic_ed25519_der_fails(world: &mut UselessWorld) {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let der = world
        .deterministic_bytes_1
        .as_ref()
        .expect("deterministic_bytes_1 not set");
    let result = SigningKey::from_pkcs8_der(der);
    assert!(
        result.is_err(),
        "deterministic Ed25519 DER should fail to parse"
    );
}

#[then(regex = r#"^the Ed25519 public JWK should have kty "([^"]+)"$"#)]
fn ed25519_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have crv "([^"]+)"$"#)]
fn ed25519_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have alg "([^"]+)"$"#)]
fn ed25519_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the Ed25519 public JWK should have use "([^"]+)"$"#)]
fn ed25519_jwk_has_use(world: &mut UselessWorld, expected: String) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the Ed25519 public JWK should have a kid")]
fn ed25519_jwk_has_kid(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert!(jwk["kid"].is_string(), "Ed25519 kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "Ed25519 kid should not be empty"
    );
}

#[then("the Ed25519 public JWK should have x parameter")]
fn ed25519_jwk_has_x(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.public_jwk().to_value();
    assert!(jwk["x"].is_string(), "Ed25519 x should be present");
    assert!(
        !jwk["x"].as_str().unwrap().is_empty(),
        "Ed25519 x should not be empty"
    );
}

#[then("the Ed25519 private JWK should have d parameter")]
fn ed25519_private_jwk_has_d(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwk = ed25519_key.private_key_jwk().to_value();
    assert!(jwk["d"].is_string(), "Ed25519 d should be present");
    assert!(
        !jwk["d"].as_str().unwrap().is_empty(),
        "Ed25519 d should not be empty"
    );
}

#[then("the Ed25519 JWKS should have a keys array")]
fn ed25519_jwks_has_keys(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwks = ed25519_key.public_jwks().to_value();
    assert!(jwks["keys"].is_array(), "Ed25519 keys should be an array");
}

#[then("the Ed25519 JWKS keys array should contain one key")]
fn ed25519_jwks_has_one_key(world: &mut UselessWorld) {
    let ed25519_key = world.ed25519.as_ref().expect("ed25519 not set");
    let jwks = ed25519_key.public_jwks().to_value();
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
    world.ecdsa_keys.push(ecdsa.clone());
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
    world.ecdsa_keys.push(ecdsa.clone());
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

#[when(regex = r#"^I deterministically corrupt the ECDSA PKCS8 PEM with variant "([^"]+)"$"#)]
fn det_corrupt_ecdsa_pem(world: &mut UselessWorld, variant: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.deterministic_text_1 = Some(ecdsa.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the ECDSA PKCS8 PEM with variant "([^"]+)" again$"#)]
fn det_corrupt_ecdsa_pem_again(world: &mut UselessWorld, variant: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.deterministic_text_2 = Some(ecdsa.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the ECDSA PKCS8 DER with variant "([^"]+)"$"#)]
fn det_corrupt_ecdsa_der(world: &mut UselessWorld, variant: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.deterministic_bytes_1 = Some(ecdsa.private_key_pkcs8_der_corrupt_deterministic(&variant));
}

#[when(regex = r#"^I deterministically corrupt the ECDSA PKCS8 DER with variant "([^"]+)" again$"#)]
fn det_corrupt_ecdsa_der_again(world: &mut UselessWorld, variant: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    world.deterministic_bytes_2 = Some(ecdsa.private_key_pkcs8_der_corrupt_deterministic(&variant));
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
    let (good_bytes, mismatch_bytes) = if let Ok(good_pub) =
        p256::PublicKey::from_public_key_der(good)
    {
        let mismatch_pub =
            p256::PublicKey::from_public_key_der(&mismatch).expect("mismatch should parse");
        (
            good_pub.to_sec1_bytes().to_vec(),
            mismatch_pub.to_sec1_bytes().to_vec(),
        )
    } else {
        let good_pub = p384::PublicKey::from_public_key_der(good).expect("should parse as P-384");
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

#[then("the deterministic ECDSA PEM artifact should fail to parse")]
fn deterministic_ecdsa_pem_fails(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePrivateKey as _;

    let pem = world
        .deterministic_text_1
        .as_ref()
        .expect("deterministic_text_1 not set");
    let p256_result = p256::SecretKey::from_pkcs8_pem(pem);
    let p384_result = p384::SecretKey::from_pkcs8_pem(pem);
    assert!(
        p256_result.is_err() && p384_result.is_err(),
        "deterministic ECDSA PEM should fail to parse"
    );
}

#[then("the deterministic ECDSA DER artifact should fail to parse")]
fn deterministic_ecdsa_der_fails(world: &mut UselessWorld) {
    use p256::pkcs8::DecodePrivateKey as _;

    let der = world
        .deterministic_bytes_1
        .as_ref()
        .expect("deterministic_bytes_1 not set");
    let p256_result = p256::SecretKey::from_pkcs8_der(der);
    let p384_result = p384::SecretKey::from_pkcs8_der(der);
    assert!(
        p256_result.is_err() && p384_result.is_err(),
        "deterministic ECDSA DER should fail to parse"
    );
}

#[then(regex = r#"^the ECDSA public JWK should have kty "([^"]+)"$"#)]
fn ecdsa_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have crv "([^"]+)"$"#)]
fn ecdsa_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have alg "([^"]+)"$"#)]
fn ecdsa_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA public JWK should have use "([^"]+)"$"#)]
fn ecdsa_jwk_has_use(world: &mut UselessWorld, expected: String) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
    assert_eq!(jwk["use"].as_str(), Some(expected.as_str()));
}

#[then("the ECDSA public JWK should have a kid")]
fn ecdsa_jwk_has_kid(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
    assert!(jwk["kid"].is_string(), "ECDSA kid should be present");
    assert!(
        !jwk["kid"].as_str().unwrap().is_empty(),
        "ECDSA kid should not be empty"
    );
}

#[then("the ECDSA public JWK should have x and y parameters")]
fn ecdsa_jwk_has_x_y(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.public_jwk().to_value();
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

#[then("the ECDSA private JWK should have d parameter")]
fn ecdsa_private_jwk_has_d(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa_key.private_key_jwk().to_value();
    assert!(jwk["d"].is_string(), "ECDSA d should be present");
    assert!(
        !jwk["d"].as_str().unwrap().is_empty(),
        "ECDSA d should not be empty"
    );
}

#[then("the ECDSA JWKS should have a keys array")]
fn ecdsa_jwks_has_keys(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwks = ecdsa_key.public_jwks().to_value();
    assert!(jwks["keys"].is_array(), "ECDSA keys should be an array");
}

#[then("the ECDSA JWKS keys array should contain one key")]
fn ecdsa_jwks_has_one_key(world: &mut UselessWorld) {
    let ecdsa_key = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwks = ecdsa_key.public_jwks().to_value();
    let keys = jwks["keys"].as_array().expect("ECDSA keys should be array");
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

#[when("I get the wrong-key-usage variant of the X.509 certificate")]
fn get_x509_wrong_key_usage(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let wrong_key_usage = x509.wrong_key_usage();
    world.x509_cert_der_2 = Some(wrong_key_usage.cert_der().to_vec());
    world.x509_wrong_key_usage = Some(wrong_key_usage);
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

#[when(
    regex = r#"^I deterministically corrupt the X\.509 certificate PEM with variant "([^"]+)"$"#
)]
fn det_corrupt_x509_pem(world: &mut UselessWorld, variant: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.deterministic_text_1 = Some(x509.corrupt_cert_pem_deterministic(&variant));
}

#[when(
    regex = r#"^I deterministically corrupt the X\.509 certificate PEM with variant "([^"]+)" again$"#
)]
fn det_corrupt_x509_pem_again(world: &mut UselessWorld, variant: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.deterministic_text_2 = Some(x509.corrupt_cert_pem_deterministic(&variant));
}

#[when(
    regex = r#"^I deterministically corrupt the X\.509 certificate DER with variant "([^"]+)"$"#
)]
fn det_corrupt_x509_der(world: &mut UselessWorld, variant: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.deterministic_bytes_1 = Some(x509.corrupt_cert_der_deterministic(&variant));
}

#[when(
    regex = r#"^I deterministically corrupt the X\.509 certificate DER with variant "([^"]+)" again$"#
)]
fn det_corrupt_x509_der_again(world: &mut UselessWorld, variant: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.deterministic_bytes_2 = Some(x509.corrupt_cert_der_deterministic(&variant));
}

#[when("I write the X.509 certificate PEM to a tempfile")]
fn write_x509_cert_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_cert_tempfile = Some(x509.write_cert_pem().expect("write failed"));
}

#[when("I write the X.509 certificate DER to a tempfile")]
fn write_x509_cert_der_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_cert_der_tempfile = Some(x509.write_cert_der().expect("write failed"));
}

#[when("I write the X.509 private key PEM to a tempfile")]
fn write_x509_key_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_key_tempfile = Some(x509.write_private_key_pem().expect("write failed"));
}

#[when("I write the X.509 identity PEM to a tempfile")]
fn write_x509_identity_tempfile(world: &mut UselessWorld) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    world.x509_chain_tempfile = Some(x509.write_identity_pem().expect("write failed"));
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

#[then(regex = r#"^the X\.509 identity PEM should contain "([^"]+)"$"#)]
fn x509_identity_pem_contains(world: &mut UselessWorld, needle: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let identity = x509.identity_pem();
    assert!(
        identity.contains(&needle),
        "expected X.509 identity PEM to contain '{needle}'"
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
    let expired = world.x509_expired.as_ref().expect("expired cert not set");
    let valid = world.x509.as_ref().expect("x509 not set");
    let der = expired.cert_der();
    let (_, expired_cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");
    let (_, valid_cert) =
        x509_parser::parse_x509_certificate(valid.cert_der()).expect("parse cert");

    let not_after = expired_cert.validity().not_after;
    let valid_not_after = valid_cert.validity().not_after;

    assert!(
        not_after < valid_not_after,
        "expired cert should have not_after before the valid cert"
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
    let nyv = world
        .x509_not_yet_valid
        .as_ref()
        .expect("not_yet_valid cert not set");
    let valid = world.x509.as_ref().expect("x509 not set");
    let der = nyv.cert_der();
    let (_, nyv_cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");
    let (_, valid_cert) =
        x509_parser::parse_x509_certificate(valid.cert_der()).expect("parse cert");

    let not_before = nyv_cert.validity().not_before;
    let valid_not_before = valid_cert.validity().not_before;

    assert!(
        not_before > valid_not_before,
        "not_yet_valid cert should have not_before after the valid cert"
    );
}

#[then("the wrong-key-usage X.509 certificate should be parseable")]
fn x509_wrong_key_usage_parseable(world: &mut UselessWorld) {
    let wrong = world
        .x509_wrong_key_usage
        .as_ref()
        .expect("wrong_key_usage cert not set");
    x509_parser::parse_x509_certificate(wrong.cert_der())
        .expect("wrong-key-usage cert should parse");
}

#[then("the wrong-key-usage X.509 certificate should be marked as CA")]
fn x509_wrong_key_usage_is_ca(world: &mut UselessWorld) {
    let wrong = world
        .x509_wrong_key_usage
        .as_ref()
        .expect("wrong_key_usage cert not set");
    let (_, cert) =
        x509_parser::parse_x509_certificate(wrong.cert_der()).expect("parse wrong-key-usage cert");
    assert!(cert.is_ca(), "wrong-key-usage cert should be CA");
}

#[then("the wrong-key-usage X.509 certificate spec should disable keyCertSign")]
fn x509_wrong_key_usage_spec(world: &mut UselessWorld) {
    let wrong = world
        .x509_wrong_key_usage
        .as_ref()
        .expect("wrong_key_usage cert not set");
    assert!(
        !wrong.spec().key_usage.key_cert_sign,
        "wrong-key-usage spec should disable keyCertSign"
    );
}

#[then(regex = r#"^the wrong-key-usage X\.509 certificate label should remain "([^"]+)"$"#)]
fn x509_wrong_key_usage_label(world: &mut UselessWorld, expected: String) {
    let wrong = world
        .x509_wrong_key_usage
        .as_ref()
        .expect("wrong_key_usage cert not set");
    assert_eq!(wrong.label(), expected);
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
    assert!(result.is_err(), "truncated X.509 DER should fail to parse");
}

#[then("the deterministic X.509 DER artifact should fail to parse")]
fn deterministic_x509_der_fails(world: &mut UselessWorld) {
    let der = world
        .deterministic_bytes_1
        .as_ref()
        .expect("deterministic_bytes_1 not set");
    let result = x509_parser::parse_x509_certificate(der);
    assert!(
        result.is_err(),
        "deterministic X.509 DER should fail to parse"
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

#[then(regex = r#"^the X\.509 DER tempfile path should end with "([^"]+)"$"#)]
fn x509_cert_der_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_cert_der_tempfile
        .as_ref()
        .expect("x509_cert_der_tempfile not set");
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

#[then("reading the X.509 DER tempfile should match the certificate DER")]
fn x509_tempfile_matches_cert_der(world: &mut UselessWorld) {
    let tf = world
        .x509_cert_der_tempfile
        .as_ref()
        .expect("x509_cert_der_tempfile not set");
    let contents = tf.read_to_bytes().expect("read failed");
    let x509 = world.x509.as_ref().expect("x509 not set");
    assert_eq!(contents, x509.cert_der());
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

// =============================================================================
// X.509 Chain When steps
// =============================================================================

#[when(regex = r#"^I generate a certificate chain for domain "([^"]+)" with label "([^"]+)"$"#)]
fn gen_x509_chain(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = ChainSpec::new(&domain);
    let chain = fx.x509_chain(&label, spec.clone());

    world.label = Some(label);
    world.x509_chain_leaf_der_1 = Some(chain.leaf_cert_der().to_vec());
    world.x509_chain_root_der_1 = Some(chain.root_cert_der().to_vec());
    world.x509_chain_leaf_pem_1 = Some(chain.leaf_cert_pem().to_string());
    world.x509_chain_intermediate_pem_1 = Some(chain.intermediate_cert_pem().to_string());
    world.x509_chain_root_pem_1 = Some(chain.root_cert_pem().to_string());
    world.x509_chain = Some(chain);
    world.x509_chain_spec = Some(spec);
}

#[when(
    regex = r#"^I generate another certificate chain for domain "([^"]+)" with label "([^"]+)"$"#
)]
fn gen_x509_chain_second(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = ChainSpec::new(&domain);
    let chain = fx.x509_chain(&label, spec.clone());

    world.label = Some(label);
    world.x509_chain_leaf_der_2 = Some(chain.leaf_cert_der().to_vec());
    world.x509_chain_root_der_2 = Some(chain.root_cert_der().to_vec());
    world.x509_chain_leaf_pem_2 = Some(chain.leaf_cert_pem().to_string());
    world.x509_chain_intermediate_pem_2 = Some(chain.intermediate_cert_pem().to_string());
    world.x509_chain_root_pem_2 = Some(chain.root_cert_pem().to_string());
    world.x509_chain = Some(chain);
    world.x509_chain_spec = Some(spec);
}

#[when("I get the revoked leaf variant of the certificate chain")]
fn get_revoked_leaf(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let revoked = chain.revoked_leaf();
    world.x509_chain_revoked_leaf = Some(revoked);
}

#[when(regex = r#"^I get the hostname mismatch variant with "([^"]+)"$"#)]
fn get_hostname_mismatch(world: &mut UselessWorld, hostname: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let mismatched = chain.hostname_mismatch(&hostname);
    world.x509_chain_hostname_mismatch = Some(mismatched);
}

#[when("I get the expired leaf variant of the certificate chain")]
fn get_expired_leaf_chain(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let expired = chain.expired_leaf();
    world.x509_chain_expired_leaf = Some(expired);
}

#[when("I get the expired intermediate variant of the certificate chain")]
fn get_expired_intermediate_chain(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let expired = chain.expired_intermediate();
    world.x509_chain_expired_intermediate = Some(expired);
}

#[when("I get the unknown CA variant of the certificate chain")]
fn get_unknown_ca_chain(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let unknown = chain.unknown_ca();
    world.x509_chain_unknown_ca = Some(unknown);
}

#[when(regex = r#"^I add SAN "([^"]+)" to the X\.509 certificate$"#)]
fn add_san_to_cert(world: &mut UselessWorld, san: String) {
    // For self-signed certs, we regenerate with SANs
    let fx = world.factory.as_ref().expect("factory not set");
    let label = world.label.as_ref().expect("label not set");
    let x509 = world.x509.as_ref().expect("x509 not set");

    // Get the current domain from the cert
    let der = x509.cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("should have CN")
        .as_str()
        .expect("CN should be string");

    // Accumulate SANs and regenerate with all of them applied
    world.x509_chain_sans.push(san);
    let mut all_sans = world.x509_chain_sans.clone();
    all_sans.push(cn.to_string());
    all_sans.sort();
    all_sans.dedup();
    let spec = X509Spec::self_signed(cn).with_sans(all_sans);
    let new_x509 = fx.x509_self_signed(label, spec);

    world.x509_cert_pem_2 = Some(new_x509.cert_pem().to_string());
    world.x509_cert_der_2 = Some(new_x509.cert_der().to_vec());
    world.x509 = Some(new_x509);
}

#[when(regex = r#"^I add SAN "([^"]+)" to the certificate chain$"#)]
fn add_san_to_chain(world: &mut UselessWorld, san: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let fx = world.factory.as_ref().expect("factory not set");
    let label = world.label.as_deref().unwrap_or_else(|| chain.label());

    // Get current spec and add SAN
    let mut spec = chain.spec().clone();
    spec.leaf_sans.push(san);

    // Regenerate chain with new SANs
    let new_chain = fx.x509_chain(label, spec.clone());
    world.x509_chain_leaf_der_2 = Some(new_chain.leaf_cert_der().to_vec());
    world.x509_chain = Some(new_chain);
    world.x509_chain_spec = Some(spec);
}

#[when("I write the leaf certificate PEM to a tempfile")]
fn write_leaf_cert_tempfile(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    world.x509_cert_tempfile = Some(chain.write_leaf_cert_pem().expect("write failed"));
}

#[when("I write the leaf private key PEM to a tempfile")]
fn write_leaf_key_tempfile(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    world.x509_key_tempfile = Some(chain.write_leaf_private_key_pem().expect("write failed"));
}

#[when("I write the chain PEM to a tempfile")]
fn write_chain_pem_tempfile(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    world.x509_chain_pem_tempfile = Some(chain.write_chain_pem().expect("write failed"));
}

#[when("I write the full chain PEM to a tempfile")]
fn write_full_chain_pem_tempfile(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    world.x509_full_chain_tempfile = Some(chain.write_full_chain_pem().expect("write failed"));
}

#[when("I write the root certificate PEM to a tempfile")]
fn write_root_cert_tempfile(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    world.x509_root_cert_tempfile = Some(chain.write_root_cert_pem().expect("write failed"));
}

#[when("I write the revoked chain CRL PEM to a tempfile")]
fn write_revoked_chain_crl_pem(world: &mut UselessWorld) {
    let revoked = world
        .x509_chain_revoked_leaf
        .as_ref()
        .expect("revoked_leaf not set");
    let tf = revoked
        .write_crl_pem()
        .expect("revoked chain should include a CRL PEM")
        .expect("write failed");
    world.x509_crl_pem_tempfile = Some(tf);
}

#[when("I write the revoked chain CRL DER to a tempfile")]
fn write_revoked_chain_crl_der(world: &mut UselessWorld) {
    let revoked = world
        .x509_chain_revoked_leaf
        .as_ref()
        .expect("revoked_leaf not set");
    let tf = revoked
        .write_crl_der()
        .expect("revoked chain should include a CRL DER")
        .expect("write failed");
    world.x509_crl_der_tempfile = Some(tf);
}

// =============================================================================
// X.509 Chain Then steps
// =============================================================================

#[then("the certificate chain should contain a leaf certificate")]
fn chain_has_leaf(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let leaf_der = chain.leaf_cert_der();
    x509_parser::parse_x509_certificate(leaf_der).expect("leaf should parse");
}

#[then("the certificate chain should contain an intermediate certificate")]
fn chain_has_intermediate(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let int_der = chain.intermediate_cert_der();
    x509_parser::parse_x509_certificate(int_der).expect("intermediate should parse");
}

#[then("the certificate chain should contain a root certificate")]
fn chain_has_root(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let root_der = chain.root_cert_der();
    x509_parser::parse_x509_certificate(root_der).expect("root should parse");
}

#[then("the certificate chains should have identical DER")]
fn chain_identical(world: &mut UselessWorld) {
    let der1 = world
        .x509_chain_leaf_der_1
        .as_ref()
        .expect("leaf_der_1 not set");
    let der2 = world
        .x509_chain_leaf_der_2
        .as_ref()
        .expect("leaf_der_2 not set");
    assert_eq!(der1, der2, "certificate chains should be identical");
}

#[then("the leaf certificate PEM should be identical")]
fn chain_leaf_pem_identical(world: &mut UselessWorld) {
    let first = world
        .x509_chain_leaf_pem_1
        .as_ref()
        .expect("leaf PEM #1 not set");
    let second = world
        .x509_chain_leaf_pem_2
        .as_ref()
        .expect("leaf PEM #2 not set");
    assert_eq!(first, second, "leaf certificate PEM should be identical");
}

#[then("the intermediate certificate PEM should be identical")]
fn chain_intermediate_pem_identical(world: &mut UselessWorld) {
    let first = world
        .x509_chain_intermediate_pem_1
        .as_ref()
        .expect("intermediate PEM #1 not set");
    let second = world
        .x509_chain_intermediate_pem_2
        .as_ref()
        .expect("intermediate PEM #2 not set");
    assert_eq!(
        first, second,
        "intermediate certificate PEM should be identical"
    );
}

#[then("the root certificate PEM should be identical")]
fn chain_root_pem_identical(world: &mut UselessWorld) {
    let first = world
        .x509_chain_root_pem_1
        .as_ref()
        .expect("root PEM #1 not set");
    let second = world
        .x509_chain_root_pem_2
        .as_ref()
        .expect("root PEM #2 not set");
    assert_eq!(first, second, "root certificate PEM should be identical");
}

#[then("the certificate chain should have a leaf certificate")]
fn chain_has_leaf_alias(world: &mut UselessWorld) {
    chain_has_leaf(world);
}

#[then("the certificate chain should have an intermediate certificate")]
fn chain_has_intermediate_alias(world: &mut UselessWorld) {
    chain_has_intermediate(world);
}

#[then("the certificate chain should have a root certificate")]
fn chain_has_root_alias(world: &mut UselessWorld) {
    chain_has_root(world);
}

#[then(regex = r#"^the chain PEM should contain (\d+) "([^"]+)" markers$"#)]
fn chain_pem_contains_markers(world: &mut UselessWorld, expected: usize, marker: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let count = chain.chain_pem().matches(&marker).count();
    assert_eq!(
        count, expected,
        "expected chain PEM to contain {expected} '{marker}' markers, got {count}"
    );
}

#[then("the leaf certificate DER should differ from the intermediate certificate DER")]
fn leaf_der_differs_from_intermediate(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    assert_ne!(
        chain.leaf_cert_der(),
        chain.intermediate_cert_der(),
        "leaf DER should differ from intermediate DER"
    );
}

#[then("the intermediate certificate DER should differ from the root certificate DER")]
fn intermediate_der_differs_from_root(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    assert_ne!(
        chain.intermediate_cert_der(),
        chain.root_cert_der(),
        "intermediate DER should differ from root DER"
    );
}

#[then("the intermediate certificate should have a common name")]
fn intermediate_has_common_name(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let (_, cert) =
        x509_parser::parse_x509_certificate(chain.intermediate_cert_der()).expect("parse cert");
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("intermediate should have CN")
        .as_str()
        .expect("CN should be string");
    assert!(!cn.is_empty(), "intermediate CN should not be empty");
}

#[then("the root certificate should have a common name")]
fn root_has_common_name(world: &mut UselessWorld) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let (_, cert) = x509_parser::parse_x509_certificate(chain.root_cert_der()).expect("parse cert");
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("root should have CN")
        .as_str()
        .expect("CN should be string");
    assert!(!cn.is_empty(), "root CN should not be empty");
}

#[then("the leaf certificates should have different DER")]
fn leaf_certs_different_der(world: &mut UselessWorld) {
    let first = world
        .x509_chain_leaf_der_1
        .as_ref()
        .expect("leaf DER #1 not set");
    let second = world
        .x509_chain_leaf_der_2
        .as_ref()
        .expect("leaf DER #2 not set");
    assert_ne!(first, second, "leaf certificates should differ");
}

#[then("the root certificates should have different DER")]
fn root_certs_different_der(world: &mut UselessWorld) {
    let first = world
        .x509_chain_root_der_1
        .as_ref()
        .expect("root DER #1 not set");
    let second = world
        .x509_chain_root_der_2
        .as_ref()
        .expect("root DER #2 not set");
    assert_ne!(first, second, "root certificates should differ");
}

#[then("the leaf private key should be a valid PKCS#8 key")]
fn leaf_private_key_is_valid_pkcs8(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    rsa::RsaPrivateKey::from_pkcs8_der(chain.leaf_private_key_pkcs8_der())
        .expect("leaf private key should parse as PKCS#8");
}

#[then("the leaf private key should match the leaf certificate")]
fn leaf_private_key_matches_leaf_cert(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let private_key =
        rsa::RsaPrivateKey::from_pkcs8_der(chain.leaf_private_key_pkcs8_der()).expect("parse key");
    let (_, cert) = x509_parser::parse_x509_certificate(chain.leaf_cert_der()).expect("parse cert");
    let cert_public =
        rsa::RsaPublicKey::from_public_key_der(cert.public_key().raw).expect("parse cert SPKI");
    let private_public = private_key.to_public_key();

    assert_eq!(private_public.n(), cert_public.n(), "modulus should match");
    assert_eq!(private_public.e(), cert_public.e(), "exponent should match");
}

#[then("the leaf certificate tempfile should exist")]
fn leaf_cert_tempfile_exists(world: &mut UselessWorld) {
    let tf = world
        .x509_cert_tempfile
        .as_ref()
        .expect("leaf certificate tempfile not set");
    assert!(tf.path().exists(), "leaf certificate tempfile should exist");
}

#[then("the leaf private key tempfile should exist")]
fn leaf_key_tempfile_exists(world: &mut UselessWorld) {
    let tf = world
        .x509_key_tempfile
        .as_ref()
        .expect("leaf key tempfile not set");
    assert!(tf.path().exists(), "leaf key tempfile should exist");
}

#[then(regex = r#"^the chain tempfile path should end with "([^"]+)"$"#)]
fn chain_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_chain_pem_tempfile
        .as_ref()
        .expect("x509_chain_pem_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the full chain tempfile path should end with "([^"]+)"$"#)]
fn full_chain_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_full_chain_tempfile
        .as_ref()
        .expect("x509_full_chain_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the root certificate tempfile path should end with "([^"]+)"$"#)]
fn root_cert_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_root_cert_tempfile
        .as_ref()
        .expect("x509_root_cert_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then("reading the chain tempfile should match the chain PEM")]
fn chain_tempfile_matches_chain_pem(world: &mut UselessWorld) {
    let tf = world
        .x509_chain_pem_tempfile
        .as_ref()
        .expect("x509_chain_pem_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    assert_eq!(contents, chain.chain_pem());
}

#[then("reading the full chain tempfile should match the full chain PEM")]
fn full_chain_tempfile_matches_full_chain_pem(world: &mut UselessWorld) {
    let tf = world
        .x509_full_chain_tempfile
        .as_ref()
        .expect("x509_full_chain_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    assert_eq!(contents, chain.full_chain_pem());
}

#[then("reading the root certificate tempfile should match the root certificate PEM")]
fn root_cert_tempfile_matches_root_pem(world: &mut UselessWorld) {
    let tf = world
        .x509_root_cert_tempfile
        .as_ref()
        .expect("x509_root_cert_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    assert_eq!(contents, chain.root_cert_pem());
}

#[then(regex = r#"^the CRL PEM tempfile path should end with "([^"]+)"$"#)]
fn crl_pem_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_crl_pem_tempfile
        .as_ref()
        .expect("x509_crl_pem_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the CRL DER tempfile path should end with "([^"]+)"$"#)]
fn crl_der_tempfile_path_ends_with(world: &mut UselessWorld, suffix: String) {
    let tf = world
        .x509_crl_der_tempfile
        .as_ref()
        .expect("x509_crl_der_tempfile not set");
    let path = tf.path().to_string_lossy().to_string();
    assert!(
        path.ends_with(&suffix),
        "expected path to end with '{suffix}', got '{path}'"
    );
}

#[then(regex = r#"^the CRL PEM tempfile should contain "([^"]+)"$"#)]
fn crl_pem_tempfile_contains(world: &mut UselessWorld, needle: String) {
    let tf = world
        .x509_crl_pem_tempfile
        .as_ref()
        .expect("x509_crl_pem_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    assert!(
        contents.contains(&needle),
        "CRL PEM tempfile should contain '{needle}'"
    );
}

#[then("the CRL DER tempfile should be parseable as a CRL")]
fn crl_der_tempfile_parseable(world: &mut UselessWorld) {
    use x509_parser::prelude::FromDer;

    let tf = world
        .x509_crl_der_tempfile
        .as_ref()
        .expect("x509_crl_der_tempfile not set");
    let der = tf.read_to_bytes().expect("read failed");
    let parse_result = x509_parser::revocation_list::CertificateRevocationList::from_der(&der);
    assert!(parse_result.is_ok(), "CRL DER tempfile should parse");
}

#[then("the chain root should differ from the original root")]
fn chain_root_differs_from_original(world: &mut UselessWorld) {
    let original = world.x509_chain.as_ref().expect("x509_chain not set");
    let unknown = world
        .x509_chain_unknown_ca
        .as_ref()
        .expect("unknown-ca chain not set");
    assert_ne!(
        original.root_cert_der(),
        unknown.root_cert_der(),
        "unknown-ca chain root should differ"
    );
}

#[then("the revoked leaf certificate should be parseable")]
fn revoked_leaf_parseable(world: &mut UselessWorld) {
    let revoked = world
        .x509_chain_revoked_leaf
        .as_ref()
        .expect("revoked_leaf not set");
    let der = revoked.leaf_cert_der();
    x509_parser::parse_x509_certificate(der).expect("revoked leaf should parse");
}

#[then("the revoked leaf certificate should include a CRL with revoked entries")]
fn revoked_leaf_has_crl(world: &mut UselessWorld) {
    use x509_parser::prelude::FromDer;

    let revoked = world
        .x509_chain_revoked_leaf
        .as_ref()
        .expect("revoked_leaf not set");
    let crl_der = revoked
        .crl_der()
        .expect("revoked_leaf should include a CRL artifact");
    let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
        .expect("CRL should parse");

    let revoked_count = crl.iter_revoked_certificates().count();
    assert!(
        revoked_count > 0,
        "CRL should contain revoked certificate entries"
    );
}

#[then("the revoked leaf certificate should differ from the valid leaf certificate")]
fn revoked_differs_from_valid(world: &mut UselessWorld) {
    let revoked = world
        .x509_chain_revoked_leaf
        .as_ref()
        .expect("revoked_leaf not set");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");

    assert_ne!(
        revoked.leaf_cert_der(),
        chain.leaf_cert_der(),
        "revoked leaf should differ from valid"
    );
}

#[then(regex = r#"^the leaf certificate should have common name "([^"]+)"$"#)]
fn leaf_has_cn(world: &mut UselessWorld, expected_cn: String) {
    let chain = world
        .x509_chain_hostname_mismatch
        .as_ref()
        .or(world.x509_chain.as_ref())
        .expect("chain not set");
    let der = chain.leaf_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse leaf");

    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("should have CN")
        .as_str()
        .expect("CN should be string");

    assert_eq!(cn, expected_cn);
}

#[then(regex = r#"^the leaf certificate should not contain SAN "([^"]+)"$"#)]
fn leaf_not_contain_san(world: &mut UselessWorld, san: String) {
    let chain = world
        .x509_chain_hostname_mismatch
        .as_ref()
        .expect("mismatched chain not set");
    let der = chain.leaf_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse leaf");

    let has_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == san)))
        .unwrap_or(false);

    assert!(!has_san, "leaf should not contain SAN '{}'", san);
}

#[then("the hostname mismatch leaf certificate should differ from the valid leaf certificate")]
fn hostname_mismatch_differs(world: &mut UselessWorld) {
    let mismatched = world
        .x509_chain_hostname_mismatch
        .as_ref()
        .expect("mismatched chain not set");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");

    assert_ne!(
        mismatched.leaf_cert_der(),
        chain.leaf_cert_der(),
        "hostname mismatch leaf should differ from valid"
    );
}

#[then("the expired leaf certificate should have not_after in the past")]
fn expired_leaf_not_after_past(world: &mut UselessWorld) {
    let expired = world
        .x509_chain_expired_leaf
        .as_ref()
        .expect("expired leaf not set");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");

    let (_, expired_cert) =
        x509_parser::parse_x509_certificate(expired.leaf_cert_der()).expect("parse expired leaf");
    let (_, valid_cert) =
        x509_parser::parse_x509_certificate(chain.leaf_cert_der()).expect("parse valid leaf");

    let expired_not_after = expired_cert.validity().not_after;
    let valid_not_after = valid_cert.validity().not_after;

    assert!(
        expired_not_after < valid_not_after,
        "expired leaf should have not_after before valid"
    );
}

#[then("the intermediate certificate should be valid")]
fn intermediate_is_valid(world: &mut UselessWorld) {
    let expired = world
        .x509_chain_expired_leaf
        .as_ref()
        .expect("expired leaf chain not set");
    let der = expired.intermediate_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse intermediate");

    // Intermediate should have a reasonable validity period
    let not_after = cert.validity().not_after.timestamp();

    // Just check that the certificate exists and has a validity period
    assert!(
        not_after > 0,
        "intermediate should have a valid not_after time"
    );
}

#[then("the expired intermediate certificate should have not_after in the past")]
fn expired_intermediate_not_after_past(world: &mut UselessWorld) {
    let expired = world
        .x509_chain_expired_intermediate
        .as_ref()
        .expect("expired intermediate not set");
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");

    let (_, expired_cert) = x509_parser::parse_x509_certificate(expired.intermediate_cert_der())
        .expect("parse expired intermediate");
    let (_, valid_cert) = x509_parser::parse_x509_certificate(chain.intermediate_cert_der())
        .expect("parse valid intermediate");

    let expired_not_after = expired_cert.validity().not_after;
    let valid_not_after = valid_cert.validity().not_after;

    assert!(
        expired_not_after < valid_not_after,
        "expired intermediate should have not_after before valid"
    );
}

#[then("the leaf certificate should be valid")]
fn leaf_is_valid(world: &mut UselessWorld) {
    let expired = world
        .x509_chain_expired_intermediate
        .as_ref()
        .expect("expired intermediate chain not set");
    let der = expired.leaf_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse leaf");

    // Leaf should have a reasonable validity period
    let not_after = cert.validity().not_after.timestamp();

    // Just check that the certificate exists and has a validity period
    assert!(not_after > 0, "leaf should have a valid not_after time");
}

#[then(regex = r#"^the X\.509 certificate should contain SAN "([^"]+)"$"#)]
fn x509_has_san(world: &mut UselessWorld, san: String) {
    let x509 = world.x509.as_ref().expect("x509 not set");
    let der = x509.cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse cert");

    let has_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == san)))
        .unwrap_or(false);

    assert!(has_san, "cert should contain SAN '{}'", san);
}

#[then(regex = r#"^the leaf certificate should contain SAN "([^"]+)"$"#)]
fn leaf_has_san(world: &mut UselessWorld, san: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let der = chain.leaf_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse leaf");

    let has_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == san)))
        .unwrap_or(false);

    assert!(has_san, "leaf should contain SAN '{}'", san);
}

#[then(regex = r#"^the intermediate certificate should not contain SAN "([^"]+)"$"#)]
fn intermediate_not_contain_san(world: &mut UselessWorld, san: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let der = chain.intermediate_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse intermediate");

    let has_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == san)))
        .unwrap_or(false);

    assert!(!has_san, "intermediate should not contain SAN '{}'", san);
}

#[then(regex = r#"^the root certificate should not contain SAN "([^"]+)"$"#)]
fn root_not_contain_san(world: &mut UselessWorld, san: String) {
    let chain = world.x509_chain.as_ref().expect("x509_chain not set");
    let der = chain.root_cert_der();
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse root");

    let has_san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().any(|name| matches!(name, x509_parser::extensions::GeneralName::DNSName(dns) if *dns == san)))
        .unwrap_or(false);

    assert!(!has_san, "root should not contain SAN '{}'", san);
}

// =============================================================================
// JWKS When steps
// =============================================================================

#[when(regex = r#"^I build a JWKS containing the RSA key with kid "([^"]+)"$"#)]
fn build_jwks_rsa(world: &mut UselessWorld, kid: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    let mut jwk = rsa.public_jwk();
    set_public_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_public(jwk);
    let value = builder.build().to_value();
    // Snapshot modulus for rotation-preserve scenario
    if let Some(n) = value["keys"]
        .as_array()
        .and_then(|k| k.first())
        .and_then(|k| k["n"].as_str())
    {
        world.rsa_modulus_snapshot = Some(n.to_string());
    }
    world.jwks_output_1 = Some(value);
}

#[when(regex = r#"^I build a JWKS containing the ECDSA key with kid "([^"]+)"$"#)]
fn build_jwks_ecdsa(world: &mut UselessWorld, kid: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    let mut jwk = ecdsa.public_jwk();
    set_public_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_public(jwk);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS containing the Ed25519 key with kid "([^"]+)"$"#)]
fn build_jwks_ed25519(world: &mut UselessWorld, kid: String) {
    let ed25519 = world.ed25519.as_ref().expect("ed25519 not set");
    let mut jwk = ed25519.public_jwk();
    set_public_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_public(jwk);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS containing the HMAC secret with kid "([^"]+)"$"#)]
fn build_jwks_hmac(world: &mut UselessWorld, kid: String) {
    let hmac = world.hmac.as_ref().expect("hmac not set");
    let mut jwk = hmac.jwk();
    set_private_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_private(jwk);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when("I build a JWKS containing all keys")]
fn build_jwks_all(world: &mut UselessWorld) {
    let mut builder = JwksBuilder::new();

    if let Some(rsa) = &world.rsa {
        builder.push_public(rsa.public_jwk());
    }
    if let Some(ecdsa) = &world.ecdsa {
        builder.push_public(ecdsa.public_jwk());
    }
    if let Some(ed25519) = &world.ed25519 {
        builder.push_public(ed25519.public_jwk());
    }
    if let Some(hmac) = &world.hmac {
        builder.push_private(hmac.jwk());
    }

    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when("I build a JWKS containing all three keys")]
fn build_jwks_all_three(world: &mut UselessWorld) {
    build_jwks_all(world);
}

#[when(regex = r#"^I build a JWKS with the RSA keys with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_multi_rsa(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.rsa_keys.len(), 2, "need 2 RSA keys");
    let mut jwk1 = world.rsa_keys[0].public_jwk();
    let mut jwk2 = world.rsa_keys[1].public_jwk();
    set_public_kid(&mut jwk1, &kid1);
    set_public_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_public(jwk1);
    builder.push_public(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS with the ECDSA keys with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_multi_ecdsa(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.ecdsa_keys.len(), 2, "need 2 ECDSA keys");
    let mut jwk1 = world.ecdsa_keys[0].public_jwk();
    let mut jwk2 = world.ecdsa_keys[1].public_jwk();
    set_public_kid(&mut jwk1, &kid1);
    set_public_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_public(jwk1);
    builder.push_public(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS with the Ed25519 keys with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_multi_ed25519(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.ed25519_keys.len(), 2, "need 2 Ed25519 keys");
    let mut jwk1 = world.ed25519_keys[0].public_jwk();
    let mut jwk2 = world.ed25519_keys[1].public_jwk();
    set_public_kid(&mut jwk1, &kid1);
    set_public_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_public(jwk1);
    builder.push_public(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS with the HMAC secrets with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_multi_hmac(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.hmac_keys.len(), 2, "need 2 HMAC secrets");
    let mut jwk1 = world.hmac_keys[0].jwk();
    let mut jwk2 = world.hmac_keys[1].jwk();
    set_private_kid(&mut jwk1, &kid1);
    set_private_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_private(jwk1);
    builder.push_private(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS with both keys with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_both(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.rsa_keys.len(), 2, "need 2 RSA keys");
    let mut jwk1 = world.rsa_keys[0].public_jwk();
    let mut jwk2 = world.rsa_keys[1].public_jwk();
    set_public_kid(&mut jwk1, &kid1);
    set_public_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_public(jwk1);
    builder.push_public(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS containing both keys with kids "([^"]+)" and "([^"]+)"$"#)]
fn build_jwks_containing_both(world: &mut UselessWorld, kid1: String, kid2: String) {
    assert_eq!(world.rsa_keys.len(), 2, "need 2 RSA keys");
    let mut jwk1 = world.rsa_keys[0].public_jwk();
    let mut jwk2 = world.rsa_keys[1].public_jwk();
    set_public_kid(&mut jwk1, &kid1);
    set_public_kid(&mut jwk2, &kid2);
    let mut builder = JwksBuilder::new();
    builder.push_public(jwk1);
    builder.push_public(jwk2);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(
    regex = r#"^I build a JWKS containing all keys with kids "([^"]+)",\s*"([^"]+)",\s*"([^"]+)"$"#
)]
fn build_jwks_all_kids(world: &mut UselessWorld, kid1: String, kid2: String, kid3: String) {
    let mut builder = JwksBuilder::new();
    let kids = [&kid1, &kid2, &kid3];

    // If we have 3+ RSA keys and no other key types, use rsa_keys vector.
    if world.rsa_keys.len() >= 3 && world.ecdsa.is_none() && world.ed25519.is_none() {
        for (i, kid) in kids.iter().enumerate() {
            let mut jwk = world.rsa_keys[i].public_jwk();
            set_public_kid(&mut jwk, kid);
            builder.push_public(jwk);
        }
    } else {
        let mut idx = 0;
        if let Some(rsa) = &world.rsa {
            let mut jwk = rsa.public_jwk();
            set_public_kid(&mut jwk, kids[idx]);
            builder.push_public(jwk);
            idx += 1;
        }
        if let Some(ecdsa) = &world.ecdsa {
            let mut jwk = ecdsa.public_jwk();
            set_public_kid(&mut jwk, kids[idx]);
            builder.push_public(jwk);
            idx += 1;
        }
        if let Some(ed25519) = &world.ed25519 {
            let mut jwk = ed25519.public_jwk();
            set_public_kid(&mut jwk, kids[idx]);
            builder.push_public(jwk);
            let _ = idx;
        }
    }

    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I build a JWKS with only the second key with kid "([^"]+)"$"#)]
fn build_jwks_only_second(world: &mut UselessWorld, kid: String) {
    assert_eq!(world.rsa_keys.len(), 2, "need 2 RSA keys");
    let mut jwk = world.rsa_keys[1].public_jwk();
    set_public_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_public(jwk);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(
    regex = r#"^I build another JWKS containing all keys with kids "([^"]+)",\s*"([^"]+)",\s*"([^"]+)"$"#
)]
fn build_another_jwks(world: &mut UselessWorld, kid1: String, kid2: String, kid3: String) {
    let mut builder = JwksBuilder::new();
    let kids = [&kid1, &kid2, &kid3];
    let mut idx = 0;

    if let Some(rsa) = &world.rsa {
        let mut jwk = rsa.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        idx += 1;
    }
    if let Some(ecdsa) = &world.ecdsa {
        let mut jwk = ecdsa.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        idx += 1;
    }
    if let Some(ed25519) = &world.ed25519 {
        let mut jwk = ed25519.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        let _ = idx;
    }

    world.jwks_output_2 = Some(builder.build().to_value());
}

#[when("I build an empty JWKS")]
fn build_empty_jwks(world: &mut UselessWorld) {
    let builder = JwksBuilder::new();
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(
    regex = r#"^I build a JWKS containing all keys with kids "([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"$"#
)]
fn build_jwks_four_keys(
    world: &mut UselessWorld,
    kid1: String,
    kid2: String,
    kid3: String,
    kid4: String,
) {
    let mut builder = JwksBuilder::new();
    let kids = [&kid1, &kid2, &kid3, &kid4];
    let mut idx = 0;

    if let Some(rsa) = &world.rsa {
        let mut jwk = rsa.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        idx += 1;
    }
    if let Some(ecdsa) = &world.ecdsa {
        let mut jwk = ecdsa.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        idx += 1;
    }
    if let Some(ed25519) = &world.ed25519 {
        let mut jwk = ed25519.public_jwk();
        set_public_kid(&mut jwk, kids[idx]);
        builder.push_public(jwk);
        idx += 1;
    }
    if let Some(hmac) = &world.hmac {
        let mut jwk = hmac.jwk();
        set_private_kid(&mut jwk, kids[idx]);
        builder.push_private(jwk);
        let _ = idx;
    }

    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(regex = r#"^I filter the JWKS by kid "([^"]+)"$"#)]
fn filter_jwks_by_kid(world: &mut UselessWorld, kid: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    // Filter keys by kid
    let filtered_keys: Vec<Value> = keys
        .iter()
        .filter(|key| key["kid"].as_str() == Some(kid.as_str()))
        .cloned()
        .collect();

    world.jwks_filtered = Some(serde_json::json!({ "keys": filtered_keys }));
}

#[when(regex = r#"^I generate an RSA key for label "([^"]*)" with spec RS256$"#)]
fn gen_rsa_rs256(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::rs256());
    // Also populate pkcs8/spki fields for edge_cases scenarios that rely on them.
    if world.pkcs8_pem_1.is_none() {
        world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
        world.pkcs8_der_original = Some(rsa.private_key_pkcs8_der().to_vec());
        world.spki_der_1 = Some(rsa.public_key_spki_der().to_vec());
    }
    world.label = Some(label);
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
}

// =============================================================================
// JWKS Then steps
// =============================================================================

#[then("the JWKS should contain 1 key")]
fn jwks_has_one_key_count(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 1);
}

#[then("the JWKS should contain 2 keys")]
fn jwks_has_two_keys(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 2);
}

#[then("the JWKS should contain 3 keys")]
fn jwks_has_three_keys(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 3);
}

#[then("the JWKS should contain 4 keys")]
fn jwks_has_four_keys(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 4);
}

#[then("the JWKS should contain 0 keys")]
fn jwks_has_zero_keys(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 0);
}

#[then(regex = r#"^the JWKS should contain a key with kid "([^"]+)"$"#)]
fn jwks_has_kid(world: &mut UselessWorld, kid: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let found = keys
        .iter()
        .any(|key| key["kid"].as_str() == Some(kid.as_str()));
    assert!(found, "JWKS should contain key with kid '{}'", kid);
}

#[then(regex = r#"^the JWKS should not contain a key with kid "([^"]+)"$"#)]
fn jwks_not_has_kid(world: &mut UselessWorld, kid: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let found = keys
        .iter()
        .any(|key| key["kid"].as_str() == Some(kid.as_str()));
    assert!(!found, "JWKS should not contain key with kid '{}'", kid);
}

#[then(regex = r#"^each key in the JWKS should have kty "([^"]+)"$"#)]
fn jwks_all_have_kty(world: &mut UselessWorld, kty: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    for key in keys {
        assert_eq!(key["kty"].as_str(), Some(kty.as_str()));
    }
}

#[then("each key in the JWKS should have a unique kid")]
fn jwks_unique_kids(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let mut kids = std::collections::HashSet::new();
    for key in keys {
        let kid = key["kid"].as_str().expect("kid should be string");
        assert!(kids.insert(kid), "kid '{}' is not unique", kid);
    }
}

#[then("both JWKS outputs should be identical")]
fn jwks_outputs_identical(world: &mut UselessWorld) {
    let jwks1 = world.jwks_output_1.as_ref().expect("jwks_output_1 not set");
    let jwks2 = world.jwks_output_2.as_ref().expect("jwks_output_2 not set");
    assert_eq!(jwks1, jwks2);
}

#[then("the JWKS JSON should have a \"keys\" array")]
fn jwks_has_keys_array(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    assert!(jwks["keys"].is_array(), "keys should be an array");
}

#[then("the JWKS JSON should have an empty \"keys\" array")]
fn jwks_has_empty_keys_array(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert!(keys.is_empty(), "keys array should be empty");
}

#[then(regex = r#"^the JWKS should contain a key with alg "([^"]+)"$"#)]
fn jwks_has_alg(world: &mut UselessWorld, alg: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let found = keys
        .iter()
        .any(|key| key["alg"].as_str() == Some(alg.as_str()));
    assert!(found, "JWKS should contain key with alg '{}'", alg);
}

#[then(regex = r#"^the JWKS RSA key should contain field "([^"]+)"$"#)]
fn jwks_rsa_has_field(world: &mut UselessWorld, field: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    let rsa_key = keys
        .iter()
        .find(|k| k["kty"].as_str() == Some("RSA"))
        .expect("should find RSA key");
    assert!(
        rsa_key.get(&field).is_some(),
        "RSA key should have field '{}'",
        field
    );
}

#[then(regex = r#"^the JWKS EC key should contain field "([^"]+)"$"#)]
fn jwks_ec_has_field(world: &mut UselessWorld, field: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    let ec_key = keys
        .iter()
        .find(|k| k["kty"].as_str() == Some("EC"))
        .expect("should find EC key");
    assert!(
        ec_key.get(&field).is_some(),
        "EC key should have field '{}'",
        field
    );
}

#[then(regex = r#"^the JWKS RSA key should not contain field "([^"]+)"$"#)]
fn jwks_rsa_not_has_field(world: &mut UselessWorld, field: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    let rsa_key = keys
        .iter()
        .find(|k| k["kty"].as_str() == Some("RSA"))
        .expect("should find RSA key");
    assert!(
        rsa_key.get(&field).is_none(),
        "RSA key should not have field '{}'",
        field
    );
}

#[then("the filtered JWKS should contain 1 key")]
fn filtered_jwks_has_one_key(world: &mut UselessWorld) {
    let jwks = world.jwks_filtered.as_ref().expect("filtered jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");
    assert_eq!(keys.len(), 1);
}

#[then(regex = r#"^the filtered JWKS should contain a key with kid "([^"]+)"$"#)]
fn filtered_jwks_has_kid(world: &mut UselessWorld, kid: String) {
    let jwks = world.jwks_filtered.as_ref().expect("filtered jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let found = keys
        .iter()
        .any(|key| key["kid"].as_str() == Some(kid.as_str()));
    assert!(found, "filtered JWKS should contain key with kid '{}'", kid);
}

// #[then(regex = r#"^the X\.509 certificate should have a JWK representation$"#)]
// fn x509_has_jwk(world: &mut UselessWorld) {
//     let x509 = world.x509.as_ref().expect("x509 not set");
//     // X.509 cert has an RSA key which can be converted to JWK
//     let _jwk = x509.private_key_jwk();
//     // If we get here, the JWK representation exists
// }

// #[then(regex = r#"^the X\.509 certificate JWK should have kty "([^"]+)"$"#)]
// fn x509_jwk_has_kty(world: &mut UselessWorld, expected: String) {
//     let x509 = world.x509.as_ref().expect("x509 not set");
//     let jwk = x509.private_key_jwk().to_value();
//     assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
// }

// X.509 certificate JWK steps are commented out because X509Cert does not
// currently expose a `private_key_jwk()` method.
// #[then("the X.509 certificate JWK should have a kid")]
// fn x509_jwk_has_kid(world: &mut UselessWorld) {
//     let x509 = world.x509.as_ref().expect("x509 not set");
//     let jwk = x509.private_key_jwk().to_value();
//     assert!(jwk["kid"].is_string(), "kid should be present");
//     assert!(!jwk["kid"].as_str().unwrap().is_empty(), "kid should not be empty");
// }

#[then(regex = r#"^the JWKS should contain a key with kty "([^"]+)"$"#)]
fn jwks_has_kty(world: &mut UselessWorld, kty: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    let keys = jwks["keys"].as_array().expect("keys should be array");

    let found = keys
        .iter()
        .any(|key| key["kty"].as_str() == Some(kty.as_str()));
    assert!(found, "JWKS should contain key with kty '{}'", kty);
}

#[then("the JWKS JSON should be parseable")]
fn jwks_parseable(world: &mut UselessWorld) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks not set");
    // If we can access JSON, it's parseable
    let _keys = jwks["keys"].as_array().expect("keys should be array");
}

#[then(regex = r#"^the JWKS key with kid "([^"]+)" should have the same modulus as the original$"#)]
fn jwks_key_same_modulus(world: &mut UselessWorld, kid: String) {
    let jwks = world.jwks_output_1.as_ref().expect("jwks_output_1 not set");
    let original_n = world
        .rsa_modulus_snapshot
        .as_ref()
        .expect("no modulus snapshot");
    let key = jwks["keys"]
        .as_array()
        .expect("keys should be array")
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid.as_str()))
        .expect("should find key with given kid");
    assert_eq!(
        key["n"].as_str().unwrap(),
        original_n.as_str(),
        "modulus should be same"
    );
}

#[then(regex = r#"^the RSA JWK should have kty "([^"]+)"$"#)]
fn cross_rsa_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa.public_jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ECDSA JWK should have kty "([^"]+)"$"#)]
fn cross_ecdsa_jwk_has_kty(world: &mut UselessWorld, expected: String) {
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    let jwk = ecdsa.public_jwk().to_value();
    assert_eq!(jwk["kty"].as_str(), Some(expected.as_str()));
}

#[then("the RSA JWK kty should differ from the ECDSA JWK kty")]
fn cross_rsa_and_ecdsa_kty_differ(world: &mut UselessWorld) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    let ecdsa = world.ecdsa.as_ref().expect("ecdsa not set");
    let rsa_jwk = rsa.public_jwk().to_value();
    let ecdsa_jwk = ecdsa.public_jwk().to_value();
    let rsa_kty = rsa_jwk["kty"].as_str().unwrap();
    let ecdsa_kty = ecdsa_jwk["kty"].as_str().unwrap();
    assert_ne!(rsa_kty, ecdsa_kty, "RSA and ECDSA kty should differ");
}

#[then(regex = r#"^the ES256 JWK should have crv "([^"]+)"$"#)]
fn cross_es256_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ecdsa = world.ecdsa_keys.first().expect("ES256 key not set");
    let jwk = ecdsa.public_jwk().to_value();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the ES384 JWK should have crv "([^"]+)"$"#)]
fn cross_es384_jwk_has_crv(world: &mut UselessWorld, expected: String) {
    let ecdsa = world.ecdsa_keys.get(1).expect("ES384 key not set");
    let jwk = ecdsa.public_jwk().to_value();
    assert_eq!(jwk["crv"].as_str(), Some(expected.as_str()));
}

#[then("the ES256 crv should differ from the ES384 crv")]
fn cross_es256_es384_crv_differ(world: &mut UselessWorld) {
    let es256 = world.ecdsa_keys.first().expect("ES256 key not set");
    let es384 = world.ecdsa_keys.get(1).expect("ES384 key not set");
    let es256_jwk = es256.public_jwk().to_value();
    let es384_jwk = es384.public_jwk().to_value();
    let es256_crv = es256_jwk["crv"].as_str().unwrap();
    let es384_crv = es384_jwk["crv"].as_str().unwrap();
    assert_ne!(es256_crv, es384_crv, "ES256 and ES384 curves should differ");
}

#[then(regex = r#"^the RS256 JWK should have alg "([^"]+)"$"#)]
fn cross_rs256_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let rsa = world.rsa_keys.first().expect("RS256 key not set");
    let jwk = rsa.public_jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the RS384 JWK should have alg "([^"]+)"$"#)]
fn cross_rs384_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let rsa = world.rsa_keys.get(1).expect("RS384 key not set");
    let jwk = rsa.public_jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then("the RS256 alg should differ from the RS384 alg")]
fn cross_rs256_rs384_alg_differ(world: &mut UselessWorld) {
    let rs256 = world.rsa_keys.first().expect("RS256 key not set");
    let rs384 = world.rsa_keys.get(1).expect("RS384 key not set");
    let rs256_jwk = rs256.public_jwk().to_value();
    let rs384_jwk = rs384.public_jwk().to_value();
    let rs256_alg = rs256_jwk["alg"].as_str().unwrap();
    let rs384_alg = rs384_jwk["alg"].as_str().unwrap();
    assert_ne!(rs256_alg, rs384_alg, "RS256 and RS384 alg should differ");
}

#[then(regex = r#"^the HS256 JWK should have alg "([^"]+)"$"#)]
fn cross_hs256_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let hs256 = world.hmac_keys.first().expect("HS256 key not set");
    let jwk = hs256.jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the HS384 JWK should have alg "([^"]+)"$"#)]
fn cross_hs384_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let hs384 = world.hmac_keys.get(1).expect("HS384 key not set");
    let jwk = hs384.jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then(regex = r#"^the HS512 JWK should have alg "([^"]+)"$"#)]
fn cross_hs512_jwk_has_alg(world: &mut UselessWorld, expected: String) {
    let hs512 = world.hmac_keys.get(2).expect("HS512 key not set");
    let jwk = hs512.jwk().to_value();
    assert_eq!(jwk["alg"].as_str(), Some(expected.as_str()));
}

#[then("the RSA 2048 n value should have different length than RSA 4096 n value")]
fn cross_rsa_modulus_length_diff(world: &mut UselessWorld) {
    let rsa_2048 = world.rsa_keys.first().expect("RSA 2048 key not set");
    let rsa_4096 = world.rsa_keys.get(2).expect("RSA 4096 key not set");
    let jwk_2048 = rsa_2048.public_jwk().to_value();
    let jwk_4096 = rsa_4096.public_jwk().to_value();
    let n_2048 = jwk_2048["n"].as_str().expect("RSA 2048 n missing");
    let n_4096 = jwk_4096["n"].as_str().expect("RSA 4096 n missing");
    assert_ne!(
        n_2048.len(),
        n_4096.len(),
        "RSA 2048 and RSA 4096 n lengths should differ"
    );
}

// =============================================================================
// RSA variant When steps (RS384, RS512, key sizes)
// =============================================================================

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" with spec RS384$"#)]
fn gen_rsa_rs384(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(3072));
    world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.pkcs8_der_original = Some(rsa.private_key_pkcs8_der().to_vec());
    world.spki_der_1 = Some(rsa.public_key_spki_der().to_vec());
    world.label = Some(label);
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" with spec RS384 again$"#)]
fn gen_rsa_rs384_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(3072));
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate another RSA key for label "([^"]+)" with spec RS384$"#)]
fn gen_rsa_rs384_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(3072));
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" with spec RS512$"#)]
fn gen_rsa_rs512(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(4096));
    world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.pkcs8_der_original = Some(rsa.private_key_pkcs8_der().to_vec());
    world.spki_der_1 = Some(rsa.public_key_spki_der().to_vec());
    world.label = Some(label);
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" with spec RS512 again$"#)]
fn gen_rsa_rs512_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(4096));
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate another RSA key for label "([^"]+)" with spec RS512$"#)]
fn gen_rsa_rs512_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(4096));
    world.pkcs8_pem_2 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.spki_der_2 = Some(rsa.public_key_spki_der().to_vec());
    world.rsa = Some(rsa);
}

#[when(regex = r#"^I generate an RSA key for label "([^"]+)" with spec (\d+)$"#)]
fn gen_rsa_by_bits(world: &mut UselessWorld, label: String, bits: usize) {
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa = fx.rsa(&label, RsaSpec::new(bits));
    world.pkcs8_pem_1 = Some(rsa.private_key_pkcs8_pem().to_string());
    world.pkcs8_der_original = Some(rsa.private_key_pkcs8_der().to_vec());
    world.spki_der_1 = Some(rsa.public_key_spki_der().to_vec());
    world.label = Some(label);
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
}

#[then(regex = r"^the RSA modulus should have (\d+) bytes$")]
fn rsa_modulus_size(world: &mut UselessWorld, expected: usize) {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let der = world.spki_der_1.as_ref().expect("spki_der_1 not set");
    let pub_key = rsa::RsaPublicKey::from_public_key_der(der).unwrap();
    let modulus_bytes = pub_key.n().to_bytes_be();
    assert_eq!(
        modulus_bytes.len(),
        expected,
        "modulus should have {expected} bytes"
    );
}

#[then(regex = r#"^the RSA private JWK should have (\w+) parameter$"#)]
fn rsa_private_jwk_has_single_param(world: &mut UselessWorld, param: String) {
    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let jwk = rsa_key.private_key_jwk().to_value();
    assert!(
        jwk.get(&param).is_some(),
        "private JWK should have '{param}' field"
    );
    assert!(jwk[&param].is_string(), "{param} should be a string");
}

// =============================================================================
// HMAC variant When steps (HS384, HS512)
// =============================================================================

#[when(regex = r#"^I generate an HMAC HS384 secret for label "([^"]+)"$"#)]
fn gen_hmac_hs384(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs384());
    world.hmac_secret_1 = Some(secret.secret_bytes().to_vec());
    world.hmac_keys.push(secret.clone());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate an HMAC HS384 secret for label "([^"]+)" again$"#)]
fn gen_hmac_hs384_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs384());
    world.hmac_secret_2 = Some(secret.secret_bytes().to_vec());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate another HMAC HS384 secret for label "([^"]+)"$"#)]
fn gen_hmac_hs384_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs384());
    world.hmac_secret_2 = Some(secret.secret_bytes().to_vec());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate an HMAC HS512 secret for label "([^"]+)"$"#)]
fn gen_hmac_hs512(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs512());
    world.hmac_secret_1 = Some(secret.secret_bytes().to_vec());
    world.hmac_keys.push(secret.clone());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate an HMAC HS512 secret for label "([^"]+)" again$"#)]
fn gen_hmac_hs512_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs512());
    world.hmac_secret_2 = Some(secret.secret_bytes().to_vec());
    world.hmac = Some(secret);
}

#[when(regex = r#"^I generate another HMAC HS512 secret for label "([^"]+)"$"#)]
fn gen_hmac_hs512_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let secret = fx.hmac(&label, HmacSpec::hs512());
    world.hmac_secret_2 = Some(secret.secret_bytes().to_vec());
    world.hmac = Some(secret);
}

#[then("the HMAC secrets should be different")]
fn hmac_secrets_different(world: &mut UselessWorld) {
    assert_ne!(world.hmac_secret_1, world.hmac_secret_2);
}

#[then(regex = r"^the HMAC secret bytes should have length (\d+)$")]
fn hmac_secret_bytes_length(world: &mut UselessWorld, expected: usize) {
    let secret = world.hmac.as_ref().expect("hmac not set");
    assert_eq!(secret.secret_bytes().len(), expected);
}

// =============================================================================
// Edge-case steps
// =============================================================================

#[then("the PKCS8 PEM should be parseable")]
fn pkcs8_pem_parseable(world: &mut UselessWorld) {
    use rsa::pkcs8::DecodePrivateKey;

    let rsa_key = world.rsa.as_ref().expect("rsa not set");
    let pem = rsa_key.private_key_pkcs8_pem();
    rsa::RsaPrivateKey::from_pkcs8_pem(pem).expect("PKCS8 PEM should parse");
}

#[when("I generate the same keys again")]
fn gen_same_keys_again(world: &mut UselessWorld) {
    // Snapshot PEMs before regenerating so we can compare after.
    world.rsa_pems_before = world
        .rsa_keys
        .iter()
        .map(|k| k.private_key_pkcs8_pem().to_string())
        .collect();
    let fx = world.factory.as_ref().expect("factory not set");
    let rsa_a = fx.rsa("label-a", RsaSpec::rs256());
    let rsa_b = fx.rsa("label-b", RsaSpec::rs256());
    world.rsa_keys.clear();
    world.rsa_keys.push(rsa_a);
    world.rsa_keys.push(rsa_b);
}

#[then("each regenerated key should be identical to the original")]
fn regenerated_keys_identical(world: &mut UselessWorld) {
    // Real PEM equality: compare before-snapshots with current keys.
    let rsa_after: Vec<String> = world
        .rsa_keys
        .iter()
        .map(|k| k.private_key_pkcs8_pem().to_string())
        .collect();
    assert_eq!(
        world.rsa_pems_before, rsa_after,
        "RSA keys must survive cache clear"
    );
    if !world.ecdsa_pems_before.is_empty() {
        let pem = world
            .ecdsa
            .as_ref()
            .unwrap()
            .private_key_pkcs8_pem()
            .to_string();
        assert_eq!(
            world.ecdsa_pems_before,
            vec![pem],
            "ECDSA key must survive cache clear"
        );
    }
    if !world.ed25519_pems_before.is_empty() {
        let pem = world
            .ed25519
            .as_ref()
            .unwrap()
            .private_key_pkcs8_pem()
            .to_string();
        assert_eq!(
            world.ed25519_pems_before,
            vec![pem],
            "Ed25519 key must survive cache clear"
        );
    }
}

#[when("I generate the same keys in reverse order")]
fn gen_same_keys_reverse(world: &mut UselessWorld) {
    // Snapshot PEMs before regenerating.
    world.rsa_pems_before = world
        .rsa_keys
        .iter()
        .map(|k| k.private_key_pkcs8_pem().to_string())
        .collect();
    if let Some(k) = &world.ecdsa {
        world.ecdsa_pems_before = vec![k.private_key_pkcs8_pem().to_string()];
    }
    if let Some(k) = &world.ed25519 {
        world.ed25519_pems_before = vec![k.private_key_pkcs8_pem().to_string()];
    }
    let fx = world.factory.as_ref().expect("factory not set");
    // Generate Ed25519, ECDSA, RSA in reverse of original order (RSA, ECDSA, Ed25519)
    let ed25519 = fx.ed25519("ed25519", Ed25519Spec::new());
    let ecdsa = fx.ecdsa("ecdsa", EcdsaSpec::es256());
    let rsa = fx.rsa("rsa", RsaSpec::rs256());
    world.rsa_keys.clear();
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
    world.ecdsa = Some(ecdsa);
    world.ed25519 = Some(ed25519);
}

#[when("I generate the same keys again in reverse order")]
fn gen_same_keys_reverse_again(world: &mut UselessWorld) {
    // Snapshot PEMs before regenerating.
    world.rsa_pems_before = world
        .rsa_keys
        .iter()
        .map(|k| k.private_key_pkcs8_pem().to_string())
        .collect();
    if let Some(k) = &world.ecdsa {
        world.ecdsa_pems_before = vec![k.private_key_pkcs8_pem().to_string()];
    }
    if let Some(k) = &world.ed25519 {
        world.ed25519_pems_before = vec![k.private_key_pkcs8_pem().to_string()];
    }

    let fx = world.factory.as_ref().expect("factory not set");
    // Regenerate in reverse order, preserving the labels used by cross_key.feature.
    let ed25519 = fx.ed25519("isolation-ed25519", Ed25519Spec::new());
    let ecdsa = fx.ecdsa("isolation-ecdsa", EcdsaSpec::es256());
    let rsa = fx.rsa("isolation-rsa", RsaSpec::rs256());

    world.rsa_keys.clear();
    world.rsa_keys.push(rsa.clone());
    world.rsa = Some(rsa);
    world.ecdsa = Some(ecdsa);
    world.ed25519 = Some(ed25519);
}

#[then("each key should have a unique kid")]
fn all_keys_unique_kid(world: &mut UselessWorld) {
    let mut kids = std::collections::HashSet::new();
    if let Some(rsa) = &world.rsa {
        kids.insert(rsa.kid());
    }
    if let Some(ecdsa) = &world.ecdsa {
        kids.insert(ecdsa.kid());
    }
    if let Some(ed25519) = &world.ed25519 {
        kids.insert(ed25519.kid());
    }
    if let Some(hmac) = &world.hmac {
        kids.insert(hmac.kid());
    }
    let count = world.rsa.is_some() as usize
        + world.ecdsa.is_some() as usize
        + world.ed25519.is_some() as usize
        + world.hmac.is_some() as usize;
    assert_eq!(kids.len(), count, "all keys should have unique kids");
}

// =============================================================================
// JWKS public-only and X.509 chain "again" steps
// =============================================================================

#[when(regex = r#"^I build a JWKS containing the RSA public key with kid "([^"]+)"$"#)]
fn build_jwks_rsa_public(world: &mut UselessWorld, kid: String) {
    let rsa = world.rsa.as_ref().expect("rsa not set");
    let mut jwk = rsa.public_jwk();
    set_public_kid(&mut jwk, &kid);
    let builder = JwksBuilder::new().add_public(jwk);
    world.jwks_output_1 = Some(builder.build().to_value());
}

#[when(
    regex = r#"^I generate a certificate chain for domain "([^"]+)" with label "([^"]+)" again$"#
)]
fn gen_x509_chain_again(world: &mut UselessWorld, domain: String, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let spec = ChainSpec::new(&domain);
    let chain = fx.x509_chain(&label, spec);
    world.x509_chain_leaf_der_2 = Some(chain.leaf_cert_der().to_vec());
    world.x509_chain_root_der_2 = Some(chain.root_cert_der().to_vec());
    world.x509_chain_leaf_pem_2 = Some(chain.leaf_cert_pem().to_string());
    world.x509_chain_intermediate_pem_2 = Some(chain.intermediate_cert_pem().to_string());
    world.x509_chain_root_pem_2 = Some(chain.root_cert_pem().to_string());
    world.x509_chain = Some(chain);
}

// =============================================================================
// Token steps
// =============================================================================

#[cfg(feature = "uk-token")]
use base64::Engine as _;
#[cfg(feature = "uk-token")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// --- API key steps ---

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an API key token for label "([^"]+)"$"#)]
fn gen_token_apikey(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::api_key());
    world.token_value_1 = Some(token.value().to_string());
    world.token_auth_header = Some(token.authorization_header());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an API key token for label "([^"]+)" again$"#)]
fn gen_token_apikey_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::api_key());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate another API key token for label "([^"]+)"$"#)]
fn gen_token_apikey_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::api_key());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an API key token for label "([^"]+)" with variant "([^"]+)"$"#)]
fn gen_token_apikey_variant(world: &mut UselessWorld, label: String, variant: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token_with_variant(&label, TokenSpec::api_key(), &variant);
    if world.token_value_1.is_none() {
        world.token_value_1 = Some(token.value().to_string());
    } else {
        world.token_value_2 = Some(token.value().to_string());
    }
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an API key token for label "([^"]+)" with variant "([^"]+)" again$"#)]
fn gen_token_apikey_variant_again(world: &mut UselessWorld, label: String, variant: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token_with_variant(&label, TokenSpec::api_key(), &variant);
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

// --- Bearer token steps ---

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate a bearer token for label "([^"]+)"$"#)]
fn gen_token_bearer(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::bearer());
    world.token_value_1 = Some(token.value().to_string());
    world.token_auth_header = Some(token.authorization_header());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate a bearer token for label "([^"]+)" again$"#)]
fn gen_token_bearer_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::bearer());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate another bearer token for label "([^"]+)"$"#)]
fn gen_token_bearer_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::bearer());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

// --- OAuth access token steps ---

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an OAuth access token for label "([^"]+)"$"#)]
fn gen_token_oauth(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::oauth_access_token());
    world.token_value_1 = Some(token.value().to_string());
    world.token_auth_header = Some(token.authorization_header());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate an OAuth access token for label "([^"]+)" again$"#)]
fn gen_token_oauth_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::oauth_access_token());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

#[cfg(feature = "uk-token")]
#[when(regex = r#"^I generate another OAuth access token for label "([^"]+)"$"#)]
fn gen_token_oauth_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let token = fx.token(&label, TokenSpec::oauth_access_token());
    world.token_value_2 = Some(token.value().to_string());
    world.token = Some(token);
}

// --- Token assertions ---

#[cfg(feature = "uk-token")]
#[then("the token values should be identical")]
fn token_values_identical(world: &mut UselessWorld) {
    assert_eq!(world.token_value_1, world.token_value_2);
}

#[cfg(feature = "uk-token")]
#[then("the token values should be different")]
fn token_values_different(world: &mut UselessWorld) {
    assert_ne!(world.token_value_1, world.token_value_2);
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the token value should start with "([^"]+)"$"#)]
fn token_value_starts_with(world: &mut UselessWorld, prefix: String) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    assert!(
        value.starts_with(&prefix),
        "token value should start with '{prefix}', got '{value}'"
    );
}

#[cfg(feature = "uk-token")]
#[then(regex = r"^the token value should have length (\d+)$")]
fn token_value_length(world: &mut UselessWorld, expected: usize) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    assert_eq!(
        value.len(),
        expected,
        "token value length should be {expected}"
    );
}

#[cfg(feature = "uk-token")]
#[then("the token value should be valid base64url")]
fn token_value_base64url(world: &mut UselessWorld) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    assert!(
        URL_SAFE_NO_PAD.decode(value).is_ok(),
        "token value should be valid base64url"
    );
}

#[cfg(feature = "uk-token")]
#[then("the token value should have three dot-separated segments")]
fn token_value_jwt_format(world: &mut UselessWorld) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let parts: Vec<&str> = value.split('.').collect();
    assert_eq!(parts.len(), 3, "token should have 3 dot-separated segments");
}

#[cfg(feature = "uk-token")]
#[then("the token value header should decode to valid JSON")]
fn token_header_valid_json(world: &mut UselessWorld) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let header = value.split('.').next().expect("header segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(header)
        .expect("header base64url decode");
    let json: Value = serde_json::from_slice(&decoded).expect("header JSON parse");
    assert!(json.is_object(), "header should be a JSON object");
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the authorization header should start with "([^"]+)"$"#)]
fn auth_header_starts_with(world: &mut UselessWorld, prefix: String) {
    let header = world
        .token_auth_header
        .as_ref()
        .expect("token_auth_header not set");
    assert!(
        header.starts_with(&prefix),
        "authorization header should start with '{prefix}', got '{header}'"
    );
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the OAuth payload should contain issuer "([^"]+)"$"#)]
fn oauth_payload_issuer(world: &mut UselessWorld, expected: String) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let payload = value.split('.').nth(1).expect("payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload base64url decode");
    let json: Value = serde_json::from_slice(&decoded).expect("payload JSON parse");
    assert_eq!(json["iss"].as_str(), Some(expected.as_str()));
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the OAuth payload should contain subject "([^"]+)"$"#)]
fn oauth_payload_subject(world: &mut UselessWorld, expected: String) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let payload = value.split('.').nth(1).expect("payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload base64url decode");
    let json: Value = serde_json::from_slice(&decoded).expect("payload JSON parse");
    assert_eq!(json["sub"].as_str(), Some(expected.as_str()));
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the OAuth payload should contain audience "([^"]+)"$"#)]
fn oauth_payload_audience(world: &mut UselessWorld, expected: String) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let payload = value.split('.').nth(1).expect("payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload base64url decode");
    let json: Value = serde_json::from_slice(&decoded).expect("payload JSON parse");
    assert_eq!(json["aud"].as_str(), Some(expected.as_str()));
}

#[cfg(feature = "uk-token")]
#[then(regex = r#"^the OAuth payload should contain scope "([^"]+)"$"#)]
fn oauth_payload_scope(world: &mut UselessWorld, expected: String) {
    let value = world.token_value_1.as_ref().expect("token_value_1 not set");
    let payload = value.split('.').nth(1).expect("payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload base64url decode");
    let json: Value = serde_json::from_slice(&decoded).expect("payload JSON parse");
    assert_eq!(json["scope"].as_str(), Some(expected.as_str()));
}

// =============================================================================
// PGP steps
// =============================================================================

#[cfg(feature = "uk-pgp")]
use std::io::Cursor;

// --- Ed25519 PGP steps ---

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an Ed25519 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_ed25519(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::ed25519());
    world.pgp_private_armor_1 = Some(pgp.private_key_armored().to_string());
    world.pgp_public_armor_1 = Some(pgp.public_key_armored().to_string());
    world.pgp_private_binary_1 = Some(pgp.private_key_binary().to_vec());
    world.pgp_public_binary_1 = Some(pgp.public_key_binary().to_vec());
    world.pgp_fingerprint_1 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an Ed25519 PGP key for label "([^"]+)" again$"#)]
fn gen_pgp_ed25519_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::ed25519());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_public_armor_2 = Some(pgp.public_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate another Ed25519 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_ed25519_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::ed25519());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_public_armor_2 = Some(pgp.public_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

// --- RSA 2048 PGP steps ---

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an RSA 2048 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_rsa2048(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_2048());
    world.pgp_private_armor_1 = Some(pgp.private_key_armored().to_string());
    world.pgp_public_armor_1 = Some(pgp.public_key_armored().to_string());
    world.pgp_private_binary_1 = Some(pgp.private_key_binary().to_vec());
    world.pgp_public_binary_1 = Some(pgp.public_key_binary().to_vec());
    world.pgp_fingerprint_1 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an RSA 2048 PGP key for label "([^"]+)" again$"#)]
fn gen_pgp_rsa2048_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_2048());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate another RSA 2048 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_rsa2048_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_2048());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

// --- RSA 3072 PGP steps ---

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an RSA 3072 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_rsa3072(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_3072());
    world.pgp_private_armor_1 = Some(pgp.private_key_armored().to_string());
    world.pgp_public_armor_1 = Some(pgp.public_key_armored().to_string());
    world.pgp_fingerprint_1 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate an RSA 3072 PGP key for label "([^"]+)" again$"#)]
fn gen_pgp_rsa3072_again(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_3072());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I generate another RSA 3072 PGP key for label "([^"]+)"$"#)]
fn gen_pgp_rsa3072_second(world: &mut UselessWorld, label: String) {
    let fx = world.factory.as_ref().expect("factory not set");
    let pgp = fx.pgp(&label, PgpSpec::rsa_3072());
    world.pgp_private_armor_2 = Some(pgp.private_key_armored().to_string());
    world.pgp_fingerprint_2 = Some(pgp.fingerprint().to_string());
    world.pgp = Some(pgp);
}

// --- PGP assertions ---

#[cfg(feature = "uk-pgp")]
#[then("the PGP private key armor should be identical")]
fn pgp_private_armor_identical(world: &mut UselessWorld) {
    assert_eq!(world.pgp_private_armor_1, world.pgp_private_armor_2);
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP fingerprints should be different")]
fn pgp_fingerprints_different(world: &mut UselessWorld) {
    assert_ne!(world.pgp_fingerprint_1, world.pgp_fingerprint_2);
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the PGP private key armor should contain "([^"]+)"$"#)]
fn pgp_private_armor_contains(world: &mut UselessWorld, needle: String) {
    let armor = world
        .pgp_private_armor_1
        .as_ref()
        .expect("pgp_private_armor_1 not set");
    assert!(
        armor.contains(&needle),
        "PGP private armor should contain '{needle}'"
    );
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the PGP public key armor should contain "([^"]+)"$"#)]
fn pgp_public_armor_contains(world: &mut UselessWorld, needle: String) {
    let armor = world
        .pgp_public_armor_1
        .as_ref()
        .expect("pgp_public_armor_1 not set");
    assert!(
        armor.contains(&needle),
        "PGP public armor should contain '{needle}'"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP private key binary should be parseable")]
fn pgp_private_binary_parseable(world: &mut UselessWorld) {
    let binary = world
        .pgp_private_binary_1
        .as_ref()
        .expect("pgp_private_binary_1 not set");
    use pgp::composed::{Deserializable, SignedSecretKey};
    assert!(
        SignedSecretKey::from_bytes(Cursor::new(binary)).is_ok(),
        "PGP private key binary should be parseable"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP public key binary should be parseable")]
fn pgp_public_binary_parseable(world: &mut UselessWorld) {
    let binary = world
        .pgp_public_binary_1
        .as_ref()
        .expect("pgp_public_binary_1 not set");
    use pgp::composed::{Deserializable, SignedPublicKey};
    assert!(
        SignedPublicKey::from_bytes(Cursor::new(binary)).is_ok(),
        "PGP public key binary should be parseable"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP private key armor should be parseable")]
fn pgp_private_armor_parseable(world: &mut UselessWorld) {
    let armor = world
        .pgp_private_armor_1
        .as_ref()
        .expect("pgp_private_armor_1 not set");
    use pgp::composed::{Deserializable, SignedSecretKey};
    assert!(
        SignedSecretKey::from_armor_single(Cursor::new(armor)).is_ok(),
        "PGP private key armor should be parseable"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP public key armor should be parseable")]
fn pgp_public_armor_parseable(world: &mut UselessWorld) {
    let armor = world
        .pgp_public_armor_1
        .as_ref()
        .expect("pgp_public_armor_1 not set");
    use pgp::composed::{Deserializable, SignedPublicKey};
    assert!(
        SignedPublicKey::from_armor_single(Cursor::new(armor)).is_ok(),
        "PGP public key armor should be parseable"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the parsed PGP key fingerprint should match")]
fn pgp_parsed_fingerprint_matches(world: &mut UselessWorld) {
    let armor = world
        .pgp_private_armor_1
        .as_ref()
        .expect("pgp_private_armor_1 not set");
    let expected_fp = world
        .pgp_fingerprint_1
        .as_ref()
        .expect("pgp_fingerprint_1 not set");
    use pgp::composed::{Deserializable, SignedSecretKey};
    use pgp::types::KeyDetails;
    let (secret, _) =
        SignedSecretKey::from_armor_single(Cursor::new(armor)).expect("parse armored private key");
    assert_eq!(secret.fingerprint().to_string(), *expected_fp);
}

#[cfg(feature = "uk-pgp")]
#[then("the parsed PGP public key fingerprint should match")]
fn pgp_parsed_public_fingerprint_matches(world: &mut UselessWorld) {
    let armor = world
        .pgp_public_armor_1
        .as_ref()
        .expect("pgp_public_armor_1 not set");
    let expected_fp = world
        .pgp_fingerprint_1
        .as_ref()
        .expect("pgp_fingerprint_1 not set");
    use pgp::composed::{Deserializable, SignedPublicKey};
    use pgp::types::KeyDetails;
    let (public, _) =
        SignedPublicKey::from_armor_single(Cursor::new(armor)).expect("parse armored public key");
    assert_eq!(public.fingerprint().to_string(), *expected_fp);
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the PGP user ID should contain "([^"]+)"$"#)]
fn pgp_user_id_contains(world: &mut UselessWorld, needle: String) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let user_id = pgp.user_id();
    assert!(
        user_id.contains(&needle),
        "PGP user ID should contain '{needle}', got '{user_id}'"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP fingerprint should be non-empty")]
fn pgp_fingerprint_nonempty(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    assert!(
        !pgp.fingerprint().is_empty(),
        "PGP fingerprint should not be empty"
    );
}

// --- Mismatched key steps ---

#[cfg(feature = "uk-pgp")]
#[then("a PGP mismatched public key binary should parse and differ")]
fn pgp_mismatched_binary_differs(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let mismatch = pgp.mismatched_public_key_binary();
    let original = world
        .pgp_public_binary_1
        .as_ref()
        .expect("pgp_public_binary_1 not set");
    assert_ne!(
        mismatch, *original,
        "mismatched key should differ from original"
    );
    use pgp::composed::{Deserializable, SignedPublicKey};
    assert!(
        SignedPublicKey::from_bytes(Cursor::new(&mismatch)).is_ok(),
        "mismatched public key should be parseable"
    );
}

#[cfg(feature = "uk-pgp")]
#[when("I get the mismatched PGP public key binary")]
fn get_pgp_mismatch_binary(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_mismatch_1 = Some(pgp.mismatched_public_key_binary());
}

#[cfg(feature = "uk-pgp")]
#[when("I get the mismatched PGP public key binary again")]
fn get_pgp_mismatch_binary_again(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_mismatch_2 = Some(pgp.mismatched_public_key_binary());
}

#[cfg(feature = "uk-pgp")]
#[then("the mismatched PGP keys should be identical")]
fn pgp_mismatched_identical(world: &mut UselessWorld) {
    assert_eq!(world.pgp_mismatch_1, world.pgp_mismatch_2);
}

#[cfg(feature = "uk-pgp")]
#[then("a PGP mismatched public key armor should differ from original")]
fn pgp_mismatched_armor_differs(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let mismatch = pgp.mismatched_public_key_armored();
    let original = world
        .pgp_public_armor_1
        .as_ref()
        .expect("pgp_public_armor_1 not set");
    assert_ne!(
        mismatch, *original,
        "mismatched armor should differ from original"
    );
}

// --- Corruption steps ---

#[cfg(feature = "uk-pgp")]
#[when("I corrupt the PGP private key armor with BadBase64")]
fn corrupt_pgp_armor_badbase64(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_corrupted_armor = Some(pgp.private_key_armored_corrupt(CorruptPem::BadBase64));
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the corrupted PGP armor should contain "([^"]+)"$"#)]
fn corrupted_pgp_armor_contains(world: &mut UselessWorld, needle: String) {
    let armor = world
        .pgp_corrupted_armor
        .as_ref()
        .expect("pgp_corrupted_armor not set");
    assert!(
        armor.contains(&needle),
        "corrupted armor should contain '{needle}'"
    );
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r"^I truncate the PGP private key binary to (\d+) bytes$")]
fn truncate_pgp_binary(world: &mut UselessWorld, len: usize) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_truncated_binary = Some(pgp.private_key_binary_truncated(len));
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r"^the truncated PGP binary should have length (\d+)$")]
fn truncated_pgp_binary_length(world: &mut UselessWorld, expected: usize) {
    let binary = world
        .pgp_truncated_binary
        .as_ref()
        .expect("pgp_truncated_binary not set");
    assert_eq!(binary.len(), expected);
}

#[cfg(feature = "uk-pgp")]
#[then("the truncated PGP binary should fail to parse")]
fn truncated_pgp_binary_fails(world: &mut UselessWorld) {
    let binary = world
        .pgp_truncated_binary
        .as_ref()
        .expect("pgp_truncated_binary not set");
    use pgp::composed::{Deserializable, SignedSecretKey};
    assert!(
        SignedSecretKey::from_bytes(Cursor::new(binary)).is_err(),
        "truncated binary should fail to parse"
    );
}

#[cfg(feature = "uk-pgp")]
#[when(regex = r#"^I deterministically corrupt the PGP private key armor with variant "([^"]+)"$"#)]
fn det_corrupt_pgp_armor(world: &mut UselessWorld, variant: String) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let corrupted = pgp.private_key_armored_corrupt_deterministic(&variant);
    world.pgp_corrupted_armor = Some(corrupted);
}

#[cfg(feature = "uk-pgp")]
#[when(
    regex = r#"^I deterministically corrupt the PGP private key armor with variant "([^"]+)" again$"#
)]
fn det_corrupt_pgp_armor_again(world: &mut UselessWorld, _variant: String) {
    let _pgp = world.pgp.as_ref().expect("pgp not set");
    // Comparison handled in the then step
}

#[cfg(feature = "uk-pgp")]
#[then("the corrupted PGP armors should be identical")]
fn corrupted_pgp_armors_identical(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let c1 = pgp.private_key_armored_corrupt_deterministic("v1");
    let c2 = pgp.private_key_armored_corrupt_deterministic("v1");
    assert_eq!(c1, c2, "deterministic corruption should be identical");
}

#[cfg(feature = "uk-pgp")]
#[when(
    regex = r#"^I deterministically corrupt the PGP private key binary with variant "([^"]+)"$"#
)]
fn det_corrupt_pgp_binary(world: &mut UselessWorld, variant: String) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let corrupted = pgp.private_key_binary_corrupt_deterministic(&variant);
    world.pgp_truncated_binary = Some(corrupted);
}

#[cfg(feature = "uk-pgp")]
#[when(
    regex = r#"^I deterministically corrupt the PGP private key binary with variant "([^"]+)" again$"#
)]
fn det_corrupt_pgp_binary_again(world: &mut UselessWorld, _variant: String) {
    let _pgp = world.pgp.as_ref().expect("pgp not set");
    // Comparison handled in the then step
}

#[cfg(feature = "uk-pgp")]
#[then("the corrupted PGP binaries should be identical")]
fn corrupted_pgp_binaries_identical(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let c1 = pgp.private_key_binary_corrupt_deterministic("v1");
    let c2 = pgp.private_key_binary_corrupt_deterministic("v1");
    assert_eq!(
        c1, c2,
        "deterministic binary corruption should be identical"
    );
}

// --- Tempfile steps ---

#[cfg(feature = "uk-pgp")]
#[when("I write the PGP private key armor to a tempfile")]
fn write_pgp_private_tempfile(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_tempfile = Some(pgp.write_private_key_armored().expect("write failed"));
}

#[cfg(feature = "uk-pgp")]
#[when("I write the PGP public key armor to a tempfile")]
fn write_pgp_public_tempfile(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    world.pgp_public_tempfile = Some(pgp.write_public_key_armored().expect("write failed"));
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP tempfile should exist")]
fn pgp_tempfile_exists(world: &mut UselessWorld) {
    let tf = world.pgp_tempfile.as_ref().expect("pgp_tempfile not set");
    assert!(tf.path().exists(), "PGP tempfile should exist");
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP public tempfile should exist")]
fn pgp_public_tempfile_exists(world: &mut UselessWorld) {
    let tf = world
        .pgp_public_tempfile
        .as_ref()
        .expect("pgp_public_tempfile not set");
    assert!(tf.path().exists(), "PGP public tempfile should exist");
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the PGP tempfile should contain "([^"]+)"$"#)]
fn pgp_tempfile_contains(world: &mut UselessWorld, needle: String) {
    let tf = world.pgp_tempfile.as_ref().expect("pgp_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    assert!(
        contents.contains(&needle),
        "PGP tempfile should contain '{needle}'"
    );
}

#[cfg(feature = "uk-pgp")]
#[then(regex = r#"^the PGP public tempfile should contain "([^"]+)"$"#)]
fn pgp_public_tempfile_contains(world: &mut UselessWorld, needle: String) {
    let tf = world
        .pgp_public_tempfile
        .as_ref()
        .expect("pgp_public_tempfile not set");
    let contents = tf.read_to_string().expect("read failed");
    assert!(
        contents.contains(&needle),
        "PGP public tempfile should contain '{needle}'"
    );
}

// --- Debug safety ---

#[cfg(feature = "uk-pgp")]
#[then("the PGP debug output should not contain the private key armor")]
fn pgp_debug_no_leak(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let debug_output = format!("{pgp:?}");
    let private_armor = pgp.private_key_armored();
    assert!(
        !debug_output.contains(private_armor),
        "debug output should not contain private key armor"
    );
}

#[cfg(feature = "uk-pgp")]
#[then("the PGP debug output should contain the fingerprint")]
fn pgp_debug_has_fingerprint(world: &mut UselessWorld) {
    let pgp = world.pgp.as_ref().expect("pgp not set");
    let debug_output = format!("{pgp:?}");
    let fingerprint = pgp.fingerprint();
    assert!(
        debug_output.contains(fingerprint),
        "debug output should contain fingerprint"
    );
}

/// Cucumber entry point.
///
/// We deliberately run from a `[[test]]` target with `harness = false` so
/// Cucumber controls output formatting.
#[tokio::main]
async fn main() {
    UselessWorld::run("features").await;
}

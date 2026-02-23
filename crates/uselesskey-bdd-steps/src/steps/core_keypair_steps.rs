#[cfg(feature = "uk-core-keypair")]
use cucumber::{given, then, when};
#[cfg(feature = "uk-core-keypair")]
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

#[cfg(feature = "uk-core-keypair")]
const CORE_KEYPAIR_PKCS8_DER: &[u8] = &[0x30, 0x82, 0x01, 0x22, 0x04, 0x20, 0xAA, 0xBB];
#[cfg(feature = "uk-core-keypair")]
const CORE_KEYPAIR_SPKI_DER: &[u8] = &[0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86];
#[cfg(feature = "uk-core-keypair")]
const CORE_KEYPAIR_PKCS8_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\nMHg=\n-----END PRIVATE KEY-----\n";
#[cfg(feature = "uk-core-keypair")]
const CORE_KEYPAIR_SPKI_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n";

#[cfg(feature = "uk-core-keypair")]
fn sample_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        CORE_KEYPAIR_PKCS8_DER.to_vec(),
        CORE_KEYPAIR_PKCS8_PEM.to_string(),
        CORE_KEYPAIR_SPKI_DER.to_vec(),
        CORE_KEYPAIR_SPKI_PEM.to_string(),
    )
}

#[cfg(feature = "uk-core-keypair")]
#[given("I have a sample PKCS8/SPKI fixture for core-keypair")]
fn core_keypair_given_fixture(world: &mut crate::UselessWorld) {
    world.core_keypair_material = Some(sample_material());
}

#[cfg(feature = "uk-core-keypair")]
#[when(regex = r#"^I deterministically core-keypair corrupt PKCS8 PEM with variant "([^"]+)"$"#)]
fn core_keypair_corrupt_pem(world: &mut crate::UselessWorld, variant: String) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    world.deterministic_text_1 =
        Some(material.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[cfg(feature = "uk-core-keypair")]
#[when(
    regex = r#"^I deterministically core-keypair corrupt PKCS8 PEM with variant "([^"]+)" again$"#
)]
fn core_keypair_corrupt_pem_again(world: &mut crate::UselessWorld, variant: String) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    world.deterministic_text_2 =
        Some(material.private_key_pkcs8_pem_corrupt_deterministic(&variant));
}

#[cfg(feature = "uk-core-keypair")]
#[when(regex = r#"^I truncate the core-keypair PKCS8 DER to (\d+) bytes$"#)]
fn core_keypair_truncate(world: &mut crate::UselessWorld, len: usize) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    world.truncated_der = Some(material.private_key_pkcs8_der_truncated(len));
}

#[cfg(feature = "uk-core-keypair")]
#[when("I derive a core-keypair kid")]
fn core_keypair_kid(world: &mut crate::UselessWorld) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    if world.core_kid_first.is_none() {
        world.core_kid_first = Some(material.kid());
    } else {
        world.core_kid_second = Some(material.kid());
    }
}

#[cfg(feature = "uk-core-keypair")]
#[when("I write core-keypair PEM artifacts to tempfiles")]
fn core_keypair_write_tempfiles(world: &mut crate::UselessWorld) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    world.private_tempfile = Some(
        material
            .write_private_key_pkcs8_pem()
            .expect("write private tempfile"),
    );
    world.public_tempfile = Some(
        material
            .write_public_key_spki_pem()
            .expect("write public tempfile"),
    );
}

#[cfg(feature = "uk-core-keypair")]
#[then("the first and second core-keypair kids should be identical")]
fn core_keypair_kids_identical(world: &mut crate::UselessWorld) {
    assert_eq!(world.core_kid_first, world.core_kid_second);
}

#[cfg(feature = "uk-core-keypair")]
#[then("the core-keypair deterministic PEM should differ from the original")]
fn core_keypair_corrupts_text(world: &mut crate::UselessWorld) {
    let material = world
        .core_keypair_material
        .as_ref()
        .expect("core-keypair material not set");
    let corrupted = world
        .deterministic_text_1
        .as_ref()
        .expect("deterministic_text_1 not set");
    assert_ne!(corrupted, material.private_key_pkcs8_pem());
}

#[cfg(feature = "uk-core-keypair")]
#[then("the core-keypair private and public tempfiles should contain PEM headers")]
fn core_keypair_tempfiles_contain_headers(world: &mut crate::UselessWorld) {
    let private = world
        .private_tempfile
        .as_ref()
        .expect("private tempfile not set");
    let public = world
        .public_tempfile
        .as_ref()
        .expect("public tempfile not set");

    let private_text = private.read_to_string().expect("read private tempfile");
    let public_text = public.read_to_string().expect("read public tempfile");

    assert!(private_text.contains("BEGIN PRIVATE KEY"));
    assert!(public_text.contains("BEGIN PUBLIC KEY"));
}

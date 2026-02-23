#[cfg(feature = "uk-core-negative")]
use cucumber::{given, when};
#[cfg(feature = "uk-core-negative")]
use uselesskey_core_negative::{corrupt_pem_deterministic, truncate_der};

const CORE_NEGATIVE_PEM_FIXTURE: &str =
    "-----BEGIN PRIVATE KEY-----\nMHg=\n-----END PRIVATE KEY-----\n";
const CORE_NEGATIVE_DER_FIXTURE: &[u8] = &[0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09];

#[cfg(feature = "uk-core-negative")]
#[given("I have a sample PEM fixture for core-negative")]
fn core_negative_given_pem(world: &mut crate::UselessWorld) {
    world.corrupted_pem = Some(CORE_NEGATIVE_PEM_FIXTURE.to_string());
}

#[cfg(feature = "uk-core-negative")]
#[given("I have a sample DER fixture for core-negative")]
fn core_negative_given_der(world: &mut crate::UselessWorld) {
    world.truncated_der = Some(CORE_NEGATIVE_DER_FIXTURE.to_vec());
}

#[cfg(feature = "uk-core-negative")]
#[when(regex = r#"^I core-negatively corrupt the sample PEM with variant "([^"]+)"$"#)]
fn core_negative_corrupt_pem(world: &mut crate::UselessWorld, variant: String) {
    let base = world.corrupted_pem.as_ref().expect("sample PEM not set");
    world.deterministic_text_1 = Some(corrupt_pem_deterministic(base, &variant));
}

#[cfg(feature = "uk-core-negative")]
#[when(regex = r#"^I core-negatively corrupt the sample PEM with variant "([^"]+)" again$"#)]
fn core_negative_corrupt_pem_again(world: &mut crate::UselessWorld, variant: String) {
    let base = world.corrupted_pem.as_ref().expect("sample PEM not set");
    world.deterministic_text_2 = Some(corrupt_pem_deterministic(base, &variant));
}

#[cfg(feature = "uk-core-negative")]
#[when(regex = r#"^I core-negatively truncate a DER sample to (\d+) bytes$"#)]
fn core_negative_truncate_der(world: &mut crate::UselessWorld, len: usize) {
    let base = world.truncated_der.as_ref().expect("sample DER not set");
    world.truncated_der = Some(truncate_der(base, len));
}

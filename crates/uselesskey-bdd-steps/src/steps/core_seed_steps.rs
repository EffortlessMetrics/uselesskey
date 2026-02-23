#[cfg(feature = "uk-core-seed")]
use cucumber::{given, then};
#[cfg(feature = "uk-core-seed")]
use uselesskey_core_seed::Seed;

#[cfg(feature = "uk-core-seed")]
#[given(regex = r#"^a core-seed raw value "([^"]+)"$"#)]
fn core_seed_raw_value(world: &mut crate::UselessWorld, raw: String) {
    match Seed::from_env_value(&raw) {
        Ok(seed) => {
            world.core_seed_seed = Some(seed);
            world.core_seed_error = None;
        }
        Err(err) => {
            world.core_seed_seed = None;
            world.core_seed_error = Some(err);
        }
    }
}

#[cfg(feature = "uk-core-seed")]
#[then("the core-seed parse should succeed")]
fn core_seed_parse_succeeds(world: &mut crate::UselessWorld) {
    assert!(
        world.core_seed_seed.is_some(),
        "expected parsed seed, got error: {:?}",
        world.core_seed_error
    );
    assert!(world.core_seed_error.is_none());
}

#[cfg(feature = "uk-core-seed")]
#[then("the core-seed parse should fail")]
fn core_seed_parse_fails(world: &mut crate::UselessWorld) {
    assert!(world.core_seed_seed.is_none());
    assert!(world.core_seed_error.is_some());
}

#[cfg(feature = "uk-core-seed")]
#[then("the core-seed debug output should be redacted")]
fn core_seed_debug_redacted(world: &mut crate::UselessWorld) {
    let seed = world
        .core_seed_seed
        .as_ref()
        .expect("core-seed parse should have succeeded");
    assert_eq!(format!("{seed:?}"), "Seed(**redacted**)");
}

#[cfg(feature = "uk-core-seed")]
#[then(regex = r"^the core-seed last byte should be (\d+)$")]
fn core_seed_last_byte(world: &mut crate::UselessWorld, expected: u8) {
    let seed = world
        .core_seed_seed
        .as_ref()
        .expect("core-seed parse should have succeeded");
    assert_eq!(seed.bytes()[31], expected);
}

#[cfg(feature = "uk-core-seed")]
#[then(regex = r#"^the core-seed error should contain "([^"]+)"$"#)]
fn core_seed_error_contains(world: &mut crate::UselessWorld, needle: String) {
    let err = world
        .core_seed_error
        .as_ref()
        .expect("core-seed parse should have failed");
    assert!(
        err.contains(&needle),
        "expected error to contain '{needle}', got '{err}'"
    );
}

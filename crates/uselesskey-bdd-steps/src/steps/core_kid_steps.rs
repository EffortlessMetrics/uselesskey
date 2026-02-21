#[cfg(feature = "uk-core-kid")]
use base64::Engine as _;
#[cfg(feature = "uk-core-kid")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
#[cfg(feature = "uk-core-kid")]
use cucumber::{then, when};
#[cfg(feature = "uk-core-kid")]
use uselesskey_core_kid::{kid_from_bytes, kid_from_bytes_with_prefix};

#[cfg(feature = "uk-core-kid")]
#[when(regex = r#"^I derive a core-kid from bytes "([^"]+)"$"#)]
fn core_kid_derive(world: &mut crate::UselessWorld, bytes: String) {
    let kid = kid_from_bytes(bytes.as_bytes());
    if world.core_kid_first.is_none() {
        world.core_kid_first = Some(kid);
    } else {
        world.core_kid_second = Some(kid);
    }
}

#[cfg(feature = "uk-core-kid")]
#[when(regex = r#"^I derive a core-kid with prefix (\d+) from bytes "([^"]+)"$"#)]
fn core_kid_derive_with_prefix(world: &mut crate::UselessWorld, prefix: usize, bytes: String) {
    let kid = kid_from_bytes_with_prefix(bytes.as_bytes(), prefix);
    if world.core_kid_first.is_none() {
        world.core_kid_first = Some(kid);
    } else {
        world.core_kid_second = Some(kid);
    }
}

#[cfg(feature = "uk-core-kid")]
#[then("the first and second derived core-kids should be identical")]
fn core_kid_equal(world: &mut crate::UselessWorld) {
    assert_eq!(world.core_kid_first, world.core_kid_second);
}

#[cfg(feature = "uk-core-kid")]
#[then("the first and second derived core-kids should be different")]
fn core_kid_different(world: &mut crate::UselessWorld) {
    assert_ne!(world.core_kid_first, world.core_kid_second);
}

#[cfg(feature = "uk-core-kid")]
#[then(regex = r#"^the derived core-kid should decode to (\d+) bytes$"#)]
fn core_kid_decoded_len(world: &mut crate::UselessWorld, expected_len: usize) {
    let kid = world
        .core_kid_first
        .as_ref()
        .expect("core_kid_first not set");
    let decoded = URL_SAFE_NO_PAD
        .decode(kid.as_bytes())
        .expect("core-kid should be valid base64url");
    assert_eq!(decoded.len(), expected_len);
}

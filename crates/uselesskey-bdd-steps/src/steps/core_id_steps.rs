#[cfg(feature = "uk-core-id")]
use cucumber::{given, then, when};
#[cfg(feature = "uk-core-id")]
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

#[cfg(feature = "uk-core-id")]
#[given(regex = r#"^a core-id master seed "([^"]+)"$"#)]
fn core_id_master_seed(world: &mut crate::UselessWorld, raw: String) {
    world.core_id_seed_master = Some(
        Seed::from_env_value(&raw)
            .unwrap_or_else(|err| panic!("failed to parse core-id seed: {err}")),
    );
}

#[cfg(feature = "uk-core-id")]
#[when(
    regex = r#"^I derive a core-id seed with domain "([^"]+)", label "([^"]+)", spec "([^"]+)", variant "([^"]+)"$"#
)]
fn core_id_derive_seed(
    world: &mut crate::UselessWorld,
    domain: String,
    label: String,
    spec: String,
    variant: String,
) {
    let master = world
        .core_id_seed_master
        .as_ref()
        .expect("core-id master seed not set");

    let domain: &'static str = Box::leak(domain.into_boxed_str());
    let id = ArtifactId::new(
        domain,
        label,
        spec.as_bytes(),
        variant,
        DerivationVersion::V1,
    );
    let derived = derive_seed(master, &id);

    if world.core_id_seed_first.is_none() {
        world.core_id_seed_first = Some(derived);
    } else {
        world.core_id_seed_second = Some(derived);
    }
}

#[cfg(feature = "uk-core-id")]
#[then("the first and second derived core-id seeds should be identical")]
fn core_id_seeds_equal(world: &mut crate::UselessWorld) {
    assert_eq!(world.core_id_seed_first, world.core_id_seed_second);
}

#[cfg(feature = "uk-core-id")]
#[then("the first and second derived core-id seeds should be different")]
fn core_id_seeds_different(world: &mut crate::UselessWorld) {
    assert_ne!(world.core_id_seed_first, world.core_id_seed_second);
}

#[cfg(feature = "uk-core-id")]
#[then("the core-id master seed should be redacted in debug output")]
fn core_id_seed_redacted(world: &mut crate::UselessWorld) {
    let seed = world
        .core_id_seed_master
        .as_ref()
        .expect("core-id master seed not set");
    assert_eq!(format!("{seed:?}"), "Seed(**redacted**)");
}

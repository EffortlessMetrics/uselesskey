#[cfg(feature = "uk-core-factory")]
use cucumber::{then, when};
#[cfg(feature = "uk-core-factory")]
use std::panic::{AssertUnwindSafe, catch_unwind};

#[cfg(feature = "uk-core-factory")]
#[when(
    regex = r#"^I request a core-factory u64 value for domain \"([^\"]+)\", label \"([^\"]+)\", spec \"([^\"]+)\", variant \"([^\"]+)\"$"#
)]
fn core_factory_request_u64(
    world: &mut crate::UselessWorld,
    domain: String,
    label: String,
    spec: String,
    variant: String,
) {
    let domain = Box::leak(domain.into_boxed_str()) as &'static str;
    let fx = world.factory.as_ref().expect("factory not set");

    let value: u64 = *fx.get_or_init(domain, &label, spec.as_bytes(), &variant, |_rng| 0xDEADBEEF);

    if world.core_factory_value_1.is_none() {
        world.core_factory_value_1 = Some(value);
    } else {
        world.core_factory_value_2 = Some(value);
    }
}

#[cfg(feature = "uk-core-factory")]
#[when(
    regex = r#"^I request a core-factory u32 value for domain \"([^\"]+)\", label \"([^\"]+)\", spec \"([^\"]+)\", variant \"([^\"]+)\"$"#
)]
fn core_factory_request_u32(
    world: &mut crate::UselessWorld,
    domain: String,
    label: String,
    spec: String,
    variant: String,
) {
    let domain = Box::leak(domain.into_boxed_str()) as &'static str;
    let fx = world.factory.as_ref().expect("factory not set");

    let _ = fx.get_or_init(domain, &label, spec.as_bytes(), &variant, |_rng| 1234u32);
    world.core_factory_type_mismatch_panic = Some(false);
}

#[cfg(feature = "uk-core-factory")]
#[when(
    regex = r#"^I request a mismatched core-factory value for domain \"([^\"]+)\", label \"([^\"]+)\", spec \"([^\"]+)\", variant \"([^\"]+)\"$"#
)]
fn core_factory_request_mismatched_type(
    world: &mut crate::UselessWorld,
    domain: String,
    label: String,
    spec: String,
    variant: String,
) {
    let domain = Box::leak(domain.into_boxed_str()) as &'static str;
    let fx = world.factory.as_ref().expect("factory not set");

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = fx.get_or_init(domain, &label, spec.as_bytes(), &variant, |_rng| {
            "mismatch".to_string()
        });
    }));

    world.core_factory_type_mismatch_panic = Some(result.is_err());
}

#[cfg(feature = "uk-core-factory")]
#[then("the first and second core-factory values should match")]
fn core_factory_values_should_match(world: &mut crate::UselessWorld) {
    assert_eq!(world.core_factory_value_1, world.core_factory_value_2);
}

#[cfg(feature = "uk-core-factory")]
#[then("a core-factory type mismatch should panic")]
fn core_factory_type_mismatch_should_panic(world: &mut crate::UselessWorld) {
    assert_eq!(world.core_factory_type_mismatch_panic, Some(true));
}

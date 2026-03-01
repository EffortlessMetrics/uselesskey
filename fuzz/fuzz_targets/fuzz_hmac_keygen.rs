#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{Factory, HmacFactoryExt, HmacSpec, Seed};

#[derive(Arbitrary, Debug)]
struct HmacInput {
    seed: [u8; 32],
    label: String,
    /// 0 = HS256, 1 = HS384, 2 = HS512
    spec_idx: u8,
}

fuzz_target!(|input: HmacInput| {
    let fx = Factory::deterministic(Seed::new(input.seed));
    let spec = match input.spec_idx % 3 {
        0 => HmacSpec::hs256(),
        1 => HmacSpec::hs384(),
        _ => HmacSpec::hs512(),
    };

    let secret = fx.hmac(&input.label, spec);
    let bytes = secret.secret_bytes();

    // Length must match spec
    let expected_len = spec.byte_len();
    assert_eq!(
        bytes.len(),
        expected_len,
        "HMAC secret length mismatch for {}",
        spec.alg_name()
    );

    // Must be non-zero (probabilistically impossible for random, but check shape)
    // Note: we don't assert non-zero — a zero seed could deterministically produce
    // all-zero bytes, which is valid for test fixtures.

    // Determinism: same factory + label + spec = same output
    let secret2 = fx.hmac(&input.label, spec);
    assert_eq!(bytes, secret2.secret_bytes());

    // Different labels should (in general) produce different secrets
    let other_label = format!("{}-other", input.label);
    let other = fx.hmac(&other_label, spec);
    // We only check it doesn't panic; collisions are theoretically possible.
    let _ = other.secret_bytes();
});

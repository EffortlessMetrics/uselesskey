//! No-panics fuzz entrypoints for strategy profile generation.

use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use crate::{any_jwt_fixture, any_x509_chain_negative, valid_or_corrupt_jwk};

fn runner_from_bytes(data: &[u8]) -> TestRunner {
    let mut seed = [0u8; 32];
    for (idx, byte) in data.iter().take(32).enumerate() {
        seed[idx] = *byte;
    }
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &seed);
    TestRunner::new_with_rng(Config::default(), rng)
}

/// Fuzz smoke entrypoint covering major profile builders.
///
/// Intended for cargo-fuzz style harnesses: it should not panic for arbitrary input.
pub fn fuzz_profiles_no_panic(data: &[u8]) {
    let mut runner = runner_from_bytes(data);

    let _ = any_jwt_fixture().new_tree(&mut runner).map(|tree| tree.current());
    let _ = any_x509_chain_negative()
        .new_tree(&mut runner)
        .map(|tree| tree.current());
    let _ = valid_or_corrupt_jwk()
        .new_tree(&mut runner)
        .map(|tree| tree.current());
}

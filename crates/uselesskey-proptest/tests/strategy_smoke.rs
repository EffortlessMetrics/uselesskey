use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use uselesskey_proptest::{
    JwkFixture, any_jwt_fixture, any_x509_chain_negative, fuzz_entry_no_panic,
    valid_or_corrupt_jwk,
};

fn runner(seed_byte: u8) -> TestRunner {
    let seed = [seed_byte; 32];
    TestRunner::new_with_rng(
        Config {
            cases: 16,
            max_shrink_iters: 256,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    )
}

#[test]
fn deterministic_smoke_with_fixed_seed() {
    let mut run_a = runner(7);
    let mut run_b = runner(7);

    let fixture_a = any_jwt_fixture()
        .new_tree(&mut run_a)
        .expect("tree")
        .current();
    let fixture_b = any_jwt_fixture()
        .new_tree(&mut run_b)
        .expect("tree")
        .current();

    assert_eq!(format!("{fixture_a:?}"), format!("{fixture_b:?}"));
}

#[test]
fn fuzz_entrypoints_do_not_panic() {
    for sample in [
        Vec::new(),
        vec![0],
        vec![1, 2, 3, 4, 5],
        (0u8..=31u8).collect(),
        vec![255; 64],
    ] {
        fuzz_entry_no_panic(&sample);
    }
}

#[test]
fn shrink_sanity_for_corrupt_jwk() {
    let mut runner = runner(9);
    let mut tree = valid_or_corrupt_jwk().new_tree(&mut runner).expect("tree");
    let initial = format!("{:?}", tree.current()).len();

    let mut smallest = initial;
    while tree.simplify() {
        let len = format!("{:?}", tree.current()).len();
        smallest = smallest.min(len);
    }

    assert!(smallest <= initial);
}

#[test]
fn size_sanity_for_x509_negative_profile() {
    let mut runner = runner(12);
    let fixture = any_x509_chain_negative()
        .new_tree(&mut runner)
        .expect("tree")
        .current();

    let pem_len = fixture.chain.chain_pem().len();
    assert!(pem_len > 100);
}

#[test]
fn corrupt_profile_produces_invalid_json_shape() {
    let mut runner = runner(15);

    let mut saw_corrupt = false;
    for _ in 0..32 {
        let item = valid_or_corrupt_jwk()
            .new_tree(&mut runner)
            .expect("tree")
            .current();
        if let JwkFixture::CorruptJson(json) = item {
            saw_corrupt = true;
            assert!(serde_json::from_str::<serde_json::Value>(&json).is_err());
            break;
        }
    }

    assert!(saw_corrupt, "expected at least one corrupt fixture");
}

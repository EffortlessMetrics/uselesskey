//! Cache coherence integration tests for PGP.

mod testutil;

use testutil::fx;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

#[test]
fn same_label_same_spec_returns_identical_bytes() {
    let fx = fx();
    let kp1 = fx.pgp("cache-eq", PgpSpec::ed25519());
    let kp2 = fx.pgp("cache-eq", PgpSpec::ed25519());
    assert_eq!(
        kp1.private_key_binary(),
        kp2.private_key_binary(),
        "same label+spec must return identical key bytes"
    );
}

#[test]
fn different_labels_produce_different_keys() {
    let fx = fx();
    let kp_a = fx.pgp("pgp-a", PgpSpec::ed25519());
    let kp_b = fx.pgp("pgp-b", PgpSpec::ed25519());
    assert_ne!(
        kp_a.private_key_binary(),
        kp_b.private_key_binary(),
        "different labels must produce different keys"
    );
}

#[test]
fn different_specs_produce_different_keys() {
    let fx = fx();
    let kp_ed = fx.pgp("spec-diff", PgpSpec::ed25519());
    let kp_rsa = fx.pgp("spec-diff", PgpSpec::rsa_2048());
    assert_ne!(
        kp_ed.private_key_binary(),
        kp_rsa.private_key_binary(),
        "different specs must produce different keys"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.pgp("pgp-clone", PgpSpec::ed25519());
    let fx2 = fx.clone();
    let from_clone = fx2.pgp("pgp-clone", PgpSpec::ed25519());
    assert_eq!(
        _warm.private_key_binary(),
        from_clone.private_key_binary(),
        "cloned factory must share the cache"
    );
}

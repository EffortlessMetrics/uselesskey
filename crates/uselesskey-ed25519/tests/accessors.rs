use uselesskey_core::Factory;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

#[test]
fn accessors_round_trip_label_and_singleton_spec() {
    let spec = Ed25519Spec::new();
    let keypair = Factory::random().ed25519("ed25519-accessor", spec);

    assert_eq!(keypair.spec(), spec);
    assert_eq!(keypair.label(), "ed25519-accessor");
}

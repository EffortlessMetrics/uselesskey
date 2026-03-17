use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = EcdsaSpec::es384();
    let keypair = Factory::random().ecdsa("ecdsa-accessor", spec);

    assert_eq!(keypair.spec(), spec);
    assert_eq!(keypair.label(), "ecdsa-accessor");
}

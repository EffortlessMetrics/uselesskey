use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = RsaSpec::new(4096);
    let keypair = Factory::random().rsa("rsa-accessor", spec);

    assert_eq!(keypair.spec(), spec);
    assert_eq!(keypair.label(), "rsa-accessor");
}

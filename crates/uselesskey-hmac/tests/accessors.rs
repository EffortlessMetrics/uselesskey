use uselesskey_core::Factory;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = HmacSpec::hs512();
    let secret = Factory::random().hmac("hmac-accessor", spec);

    assert_eq!(secret.spec(), spec);
    assert_eq!(secret.label(), "hmac-accessor");
}

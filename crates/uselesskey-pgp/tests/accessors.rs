use uselesskey_core::Factory;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = PgpSpec::rsa_3072();
    let keypair = Factory::random().pgp("pgp-accessor", spec);

    assert_eq!(keypair.spec(), spec);
    assert_eq!(keypair.label(), "pgp-accessor");
}

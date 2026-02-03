use proptest::prelude::*;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};

use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[test]
fn pkcs8_pem_is_parseable() {
    let fx = Factory::random();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let parsed = rsa::RsaPrivateKey::from_pkcs8_pem(rsa.private_key_pkcs8_pem());
    assert!(parsed.is_ok());
}

#[test]
fn corrupt_pem_fails_to_parse() {
    let fx = Factory::random();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let bad = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    let parsed = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
    assert!(parsed.is_err());
}

#[test]
fn mismatched_public_key_is_parseable_and_different() {
    let fx = Factory::random();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let good_pub = rsa::RsaPublicKey::from_public_key_der(rsa.public_key_spki_der()).unwrap();
    let other_pub =
        rsa::RsaPublicKey::from_public_key_der(&rsa.mismatched_public_key_spki_der()).unwrap();

    // Extremely likely: modulus differs.
    assert_ne!(good_pub.n(), other_pub.n());
}

proptest! {
    #[test]
    fn deterministic_rsa_key_is_stable(seed in any::<[u8;32]>(), label in "[-_a-zA-Z0-9]{1,24}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let rsa1 = fx.rsa(&label, RsaSpec::rs256());
        let rsa2 = fx.rsa(&label, RsaSpec::rs256());

        prop_assert_eq!(rsa1.private_key_pkcs8_der(), rsa2.private_key_pkcs8_der());
        prop_assert_eq!(rsa1.public_key_spki_der(), rsa2.public_key_spki_der());
    }
}

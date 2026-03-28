use uselesskey_core::Factory;
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

pub fn rsa_material(label: &str) -> Pkcs8SpkiKeyMaterial {
    let factory = Factory::deterministic_from_str("core-keypair-tests");
    let keypair = factory.rsa(label, RsaSpec::rs256());

    Pkcs8SpkiKeyMaterial::new(
        keypair.private_key_pkcs8_der().to_vec(),
        keypair.private_key_pkcs8_pem().to_owned(),
        keypair.public_key_spki_der().to_vec(),
        keypair.public_key_spki_pem().to_owned(),
    )
}

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, Seed,
};
use uselesskey_rustcrypto::{
    RustCryptoEcdsaExt, RustCryptoEd25519Ext, RustCryptoHmacExt, RustCryptoRsaExt,
};

#[derive(Arbitrary, Debug)]
enum KeyChoice {
    RsaRs256,
    EcdsaEs256,
    EcdsaEs384,
    Ed25519,
    HmacHs256,
}

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; 32],
    label: String,
    key_choice: KeyChoice,
}

fuzz_target!(|input: Input| {
    if input.label.len() > 256 {
        return;
    }

    let fx = Factory::deterministic(Seed::new(input.seed));

    match input.key_choice {
        KeyChoice::RsaRs256 => {
            let kp = fx.rsa(&input.label, RsaSpec::rs256());
            let _private = kp.rsa_private_key();
            let _public = kp.rsa_public_key();
        }
        KeyChoice::EcdsaEs256 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es256());
            let signing_key = kp.p256_signing_key();
            let verifying_key = kp.p256_verifying_key();
            let _ = (signing_key, verifying_key);
        }
        KeyChoice::EcdsaEs384 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es384());
            let signing_key = kp.p384_signing_key();
            let verifying_key = kp.p384_verifying_key();
            let _ = (signing_key, verifying_key);
        }
        KeyChoice::Ed25519 => {
            let kp = fx.ed25519(&input.label, Ed25519Spec::new());
            let signing_key = kp.ed25519_signing_key();
            let verifying_key = kp.ed25519_verifying_key();
            let _ = (signing_key, verifying_key);
        }
        KeyChoice::HmacHs256 => {
            use hmac::Mac;
            let secret = fx.hmac(&input.label, HmacSpec::hs256());
            let mut mac = secret.hmac_sha256();
            mac.update(b"fuzz test data");
            let result = mac.finalize();
            assert_eq!(result.into_bytes().len(), 32);
        }
    }
});

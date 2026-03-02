#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, Seed,
};
use ring::signature::KeyPair;
use uselesskey_ring::{RingEcdsaKeyPairExt, RingEd25519KeyPairExt};

#[derive(Arbitrary, Debug)]
enum KeyChoice {
    EcdsaEs256,
    EcdsaEs384,
    Ed25519,
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
        KeyChoice::EcdsaEs256 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es256());
            let ring_kp = kp.ecdsa_key_pair_ring();
            assert!(!ring_kp.public_key().as_ref().is_empty());
        }
        KeyChoice::EcdsaEs384 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es384());
            let ring_kp = kp.ecdsa_key_pair_ring();
            assert!(!ring_kp.public_key().as_ref().is_empty());
        }
        KeyChoice::Ed25519 => {
            let kp = fx.ed25519(&input.label, Ed25519Spec::new());
            let ring_kp = kp.ed25519_key_pair_ring();
            assert!(!ring_kp.public_key().as_ref().is_empty());
        }
    }
});

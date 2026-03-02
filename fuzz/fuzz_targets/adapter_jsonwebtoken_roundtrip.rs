#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, Seed,
};
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Arbitrary, Debug)]
enum KeyChoice {
    EcdsaEs256,
    EcdsaEs384,
    Ed25519,
    HmacHs256,
    HmacHs384,
    HmacHs512,
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
            let _enc = kp.encoding_key();
            let _dec = kp.decoding_key();
        }
        KeyChoice::EcdsaEs384 => {
            let kp = fx.ecdsa(&input.label, EcdsaSpec::es384());
            let _enc = kp.encoding_key();
            let _dec = kp.decoding_key();
        }
        KeyChoice::Ed25519 => {
            let kp = fx.ed25519(&input.label, Ed25519Spec::new());
            let _enc = kp.encoding_key();
            let _dec = kp.decoding_key();
        }
        KeyChoice::HmacHs256 => {
            let secret = fx.hmac(&input.label, HmacSpec::hs256());
            let _enc = secret.encoding_key();
            let _dec = secret.decoding_key();
        }
        KeyChoice::HmacHs384 => {
            let secret = fx.hmac(&input.label, HmacSpec::hs384());
            let _enc = secret.encoding_key();
            let _dec = secret.decoding_key();
        }
        KeyChoice::HmacHs512 => {
            let secret = fx.hmac(&input.label, HmacSpec::hs512());
            let _enc = secret.encoding_key();
            let _dec = secret.decoding_key();
        }
    }
});

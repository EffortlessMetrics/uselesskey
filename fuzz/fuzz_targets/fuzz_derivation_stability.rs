#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, Seed, TokenFactoryExt, TokenSpec,
};

/// Verify that generating multiple key types on the same Factory
/// does not perturb each other's outputs regardless of call order.
#[derive(Arbitrary, Debug)]
struct StabilityInput {
    seed: [u8; 32],
    label_a: String,
    label_b: String,
    /// Controls call order: each bit selects which key type to generate first.
    order_bits: u8,
}

fuzz_target!(|input: StabilityInput| {
    // Limit label lengths to keep execution bounded.
    if input.label_a.len() > 128 || input.label_b.len() > 128 {
        return;
    }

    let seed = Seed::new(input.seed);

    // --- Pass 1: generate in one order ---
    let fx1 = Factory::deterministic(seed.clone());
    let results_1 = if input.order_bits & 1 == 0 {
        generate_forward(&fx1, &input.label_a, &input.label_b)
    } else {
        generate_reverse(&fx1, &input.label_a, &input.label_b)
    };

    // --- Pass 2: generate in the opposite order ---
    let fx2 = Factory::deterministic(seed);
    let results_2 = if input.order_bits & 1 == 0 {
        generate_reverse(&fx2, &input.label_a, &input.label_b)
    } else {
        generate_forward(&fx2, &input.label_a, &input.label_b)
    };

    // All artifacts must be identical regardless of generation order.
    assert_eq!(results_1.ecdsa_pem, results_2.ecdsa_pem, "ECDSA mismatch");
    assert_eq!(
        results_1.ed25519_pem, results_2.ed25519_pem,
        "Ed25519 mismatch"
    );
    assert_eq!(results_1.hmac_bytes, results_2.hmac_bytes, "HMAC mismatch");
    assert_eq!(
        results_1.token_value, results_2.token_value,
        "Token mismatch"
    );
});

struct Results {
    ecdsa_pem: String,
    ed25519_pem: String,
    hmac_bytes: Vec<u8>,
    token_value: String,
}

fn generate_forward(fx: &Factory, label_a: &str, label_b: &str) -> Results {
    let ec = fx.ecdsa(label_a, EcdsaSpec::es256());
    let ed = fx.ed25519(label_b, Ed25519Spec::new());
    let hm = fx.hmac(label_a, HmacSpec::hs256());
    let tok = fx.token(label_b, TokenSpec::bearer());
    Results {
        ecdsa_pem: ec.private_key_pkcs8_pem().to_string(),
        ed25519_pem: ed.private_key_pkcs8_pem().to_string(),
        hmac_bytes: hm.secret_bytes().to_vec(),
        token_value: tok.value().to_string(),
    }
}

fn generate_reverse(fx: &Factory, label_a: &str, label_b: &str) -> Results {
    let tok = fx.token(label_b, TokenSpec::bearer());
    let hm = fx.hmac(label_a, HmacSpec::hs256());
    let ed = fx.ed25519(label_b, Ed25519Spec::new());
    let ec = fx.ecdsa(label_a, EcdsaSpec::es256());
    Results {
        ecdsa_pem: ec.private_key_pkcs8_pem().to_string(),
        ed25519_pem: ed.private_key_pkcs8_pem().to_string(),
        hmac_bytes: hm.secret_bytes().to_vec(),
        token_value: tok.value().to_string(),
    }
}

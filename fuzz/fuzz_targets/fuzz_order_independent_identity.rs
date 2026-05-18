#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::{
    Factory, PgpFactoryExt, PgpSpec, RsaFactoryExt, RsaSpec, Seed, X509FactoryExt, X509Spec,
};

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; 32],
    label_rsa: String,
    label_pgp: String,
    label_x509: String,
    subject_cn: String,
    order: u8,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    rsa_public_der: Vec<u8>,
    pgp_fingerprint: String,
    pgp_public_binary: Vec<u8>,
    x509_cert_der: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if input.label_rsa.len() > 96
        || input.label_pgp.len() > 96
        || input.label_x509.len() > 96
        || input.subject_cn.is_empty()
        || input.subject_cn.len() > 96
    {
        return;
    }

    let seed = Seed::new(input.seed);
    let fx_a = Factory::deterministic(seed.clone());
    let fx_b = Factory::deterministic(seed);

    let a = if input.order & 1 == 0 {
        generate_forward(&fx_a, &input)
    } else {
        generate_reverse(&fx_a, &input)
    };
    let b = if input.order & 1 == 0 {
        generate_reverse(&fx_b, &input)
    } else {
        generate_forward(&fx_b, &input)
    };

    assert_eq!(a, b, "artifacts changed when generation order changed");
});

fn generate_forward(fx: &Factory, input: &Input) -> Snapshot {
    let rsa = fx.rsa(&input.label_rsa, RsaSpec::rs256());
    let pgp = fx.pgp(&input.label_pgp, PgpSpec::ed25519());
    let x509 = fx.x509_self_signed(&input.label_x509, X509Spec::self_signed(&input.subject_cn));

    Snapshot {
        rsa_public_der: rsa.public_key_spki_der().to_vec(),
        pgp_fingerprint: pgp.fingerprint().to_owned(),
        pgp_public_binary: pgp.public_key_binary().to_vec(),
        x509_cert_der: x509.cert_der().to_vec(),
    }
}

fn generate_reverse(fx: &Factory, input: &Input) -> Snapshot {
    let x509 = fx.x509_self_signed(&input.label_x509, X509Spec::self_signed(&input.subject_cn));
    let pgp = fx.pgp(&input.label_pgp, PgpSpec::ed25519());
    let rsa = fx.rsa(&input.label_rsa, RsaSpec::rs256());

    Snapshot {
        rsa_public_der: rsa.public_key_spki_der().to_vec(),
        pgp_fingerprint: pgp.fingerprint().to_owned(),
        pgp_public_binary: pgp.public_key_binary().to_vec(),
        x509_cert_der: x509.cert_der().to_vec(),
    }
}

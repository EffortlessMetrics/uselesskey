#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uselesskey::jwk::JwksBuilder;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
    negative::CorruptPem,
};
use uselesskey_cli::{materialize_manifest_to_dir, parse_materialize_manifest_str};
use uselesskey_pkcs11_mock::{Pkcs11MockFactoryExt, Pkcs11MockSpec};
use uselesskey_webauthn::{WebAuthnFactoryExt, WebAuthnSpec};

pub const REQUIRED_SCENARIO_IDS: &[&str] = &[
    "seed.derivation.v1",
    "rsa.fixture.cold",
    "rsa.fixture.warm",
    "ecdsa.fixture.p256",
    "ed25519.fixture",
    "jwk.jwks.emit",
    "hmac.fixture.hs256",
    "token.fixture.api_key",
    "x509.self_signed",
    "x509.chain",
    "negative.fixture.corrupt_pem",
    "webauthn.fixture.ceremony",
    "pkcs11.provider.construct",
    "cli.materialize_verify.shape",
];

const MATERIALIZE_VERIFY_MANIFEST: &str = r#"
version = 1

[[fixture]]
id = "entropy"
kind = "entropy.bytes"
seed = "perf-materialize"
len = 64
out = "entropy.bin"

[[fixture]]
id = "pem_shape"
kind = "pem.block_shape"
seed = "perf-materialize"
label = "test pem"
len = 128
out = "shape/test.pem"

[[fixture]]
id = "ssh_shape"
kind = "ssh.public_key_shape"
seed = "perf-materialize"
label = "deploy@example"
out = "ssh/id_ed25519.pub"
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchScenario {
    pub id: String,
    pub group: String,
    pub iterations: usize,
    pub median_ns: u64,
    pub mean_ns: u64,
    pub output_bytes: usize,
    pub allocation_bytes: Option<u64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfSummary {
    pub version: u32,
    pub generated_at_unix: u64,
    pub scenarios: Vec<BenchScenario>,
}

pub fn run_perf_suite() -> Result<PerfSummary> {
    let scenarios = vec![
        benchmark_seed_derivation(),
        benchmark("rsa.fixture.cold", "rsa", 15, || {
            let fx = Factory::random();
            let kp = fx.rsa("bench-rsa-cold", RsaSpec::rs256());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        }),
        benchmark_warm_cache_rsa(),
        benchmark("ecdsa.fixture.p256", "ecdsa", 80, || {
            let fx = Factory::random();
            let kp = fx.ecdsa("bench-ecdsa", EcdsaSpec::es256());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        }),
        benchmark("ed25519.fixture", "ed25519", 120, || {
            let fx = Factory::random();
            let kp = fx.ed25519("bench-ed25519", Ed25519Spec::new());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        }),
        benchmark_jwks_emission(),
        benchmark("hmac.fixture.hs256", "hmac", 200, || {
            let fx = Factory::random();
            let secret = fx.hmac("bench-hmac", HmacSpec::hs256());
            secret.secret_bytes().len()
        }),
        benchmark("token.fixture.api_key", "token", 300, || {
            let fx = Factory::random();
            let token = fx.token("bench-token", TokenSpec::api_key());
            token.value().len()
        }),
        benchmark("x509.self_signed", "x509", 15, || {
            let fx = Factory::random();
            let cert = fx.x509_self_signed(
                "bench-self-signed",
                X509Spec::self_signed("bench.example.com"),
            );
            cert.cert_der().len() + cert.private_key_pkcs8_der().len()
        }),
        benchmark("x509.chain", "x509", 12, || {
            let fx = Factory::random();
            let chain = fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com"));
            chain.chain_pem().len() + chain.leaf_private_key_pkcs8_pem().len()
        }),
        benchmark("negative.fixture.corrupt_pem", "negative", 80, || {
            let fx = Factory::random();
            let kp = fx.rsa("bench-negative", RsaSpec::rs256());
            let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
            let truncated = kp.private_key_pkcs8_der_truncated(32);
            corrupt.len() + truncated.len()
        }),
        benchmark_webauthn_fixture(),
        benchmark_pkcs11_provider(),
        benchmark_cli_materialize_verify()?,
    ];

    Ok(PerfSummary {
        version: 1,
        generated_at_unix: unix_now(),
        scenarios,
    })
}

fn benchmark_seed_derivation() -> BenchScenario {
    const ITERATIONS: usize = 1_000;

    let fx = Factory::deterministic_from_str("bench-seed-derivation");
    let labels = (0..ITERATIONS)
        .map(|n| format!("bench-seed-{n}"))
        .collect::<Vec<_>>();
    let mut next = 0usize;

    benchmark("seed.derivation.v1", "seed", ITERATIONS, || {
        let label = &labels[next % labels.len()];
        next += 1;
        let derived = fx.get_or_init(
            "bench:seed:derivation",
            label,
            b"seed-derivation-v1",
            "good",
            |seed| *seed.bytes(),
        );
        derived.len()
    })
}

fn benchmark_warm_cache_rsa() -> BenchScenario {
    let fx = Factory::random();
    let first = fx.rsa("bench-rsa-warm", RsaSpec::rs256());
    let output_bytes = first.private_key_pkcs8_der().len() + first.public_key_spki_der().len();
    let mut samples_ns = Vec::with_capacity(500);
    for _ in 0..500 {
        let started = Instant::now();
        let cached = fx.rsa("bench-rsa-warm", RsaSpec::rs256());
        std::hint::black_box(
            cached.private_key_pkcs8_der().len() + cached.public_key_spki_der().len(),
        );
        samples_ns.push(elapsed_ns(started.elapsed()));
    }
    BenchScenario {
        id: "rsa.fixture.warm".to_owned(),
        group: "rsa".to_owned(),
        iterations: 500,
        median_ns: median(&mut samples_ns),
        mean_ns: mean(&samples_ns),
        output_bytes,
        allocation_bytes: None,
        notes: Some("cache-hit path with pre-primed Factory".to_owned()),
    }
}

fn benchmark_jwks_emission() -> BenchScenario {
    let fx = Factory::deterministic_from_str("bench-jwks-emission");
    let rsa = fx.rsa("bench-jwks-rsa", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("bench-jwks-ecdsa", EcdsaSpec::es256());
    let ed25519 = fx.ed25519("bench-jwks-ed25519", Ed25519Spec::new());

    benchmark("jwk.jwks.emit", "jwk", 500, || {
        let jwks = JwksBuilder::new()
            .add_public(rsa.public_jwk())
            .add_public(ecdsa.public_jwk())
            .add_public(ed25519.public_jwk())
            .build();
        json_len(jwks.to_value())
    })
}

fn benchmark_webauthn_fixture() -> BenchScenario {
    let spec = WebAuthnSpec::packed("bench.example.com", b"bench-challenge");

    benchmark("webauthn.fixture.ceremony", "webauthn", 250, || {
        let fx = Factory::random();
        let registration = fx.webauthn_registration("bench-webauthn", spec.clone());
        let assertion = fx.webauthn_assertion("bench-webauthn", spec.clone());

        registration.client_data_json.len()
            + registration.authenticator_data.len()
            + registration.attestation_object.len()
            + assertion.client_data_json.len()
            + assertion.authenticator_data.len()
            + assertion.signature.len()
    })
}

fn benchmark_pkcs11_provider() -> BenchScenario {
    let mut spec = Pkcs11MockSpec::basic("HSM-BENCH");
    spec.key_labels = vec![
        "signing-key".to_string(),
        "rotation-key".to_string(),
        "audit-key".to_string(),
    ];

    benchmark("pkcs11.provider.construct", "pkcs11", 250, || {
        let fx = Factory::random();
        let provider = fx.pkcs11_mock("bench-pkcs11", spec.clone());
        let handles = provider.key_handles();
        let cert_bytes = handles
            .iter()
            .filter_map(|handle| provider.certificate_der(*handle).map(<[u8]>::len))
            .sum::<usize>();
        let signature_bytes = handles
            .first()
            .and_then(|handle| provider.sign(*handle, b"benchmark message"))
            .map_or(0, |signature| signature.len());

        provider.slot_info().serial_number.len() + cert_bytes + signature_bytes + handles.len()
    })
}

fn benchmark_cli_materialize_verify() -> Result<BenchScenario> {
    let manifest = parse_materialize_manifest_str(MATERIALIZE_VERIFY_MANIFEST)?;

    benchmark_checked("cli.materialize_verify.shape", "cli", 80, || {
        let temp = tempfile::tempdir()?;
        let written = materialize_manifest_to_dir(&manifest, temp.path(), false)?;
        let verified = materialize_manifest_to_dir(&manifest, temp.path(), true)?;
        Ok(sum_file_sizes(&written.files)? + verified.files.len())
    })
}

fn benchmark(
    id: &str,
    group: &str,
    iterations: usize,
    mut f: impl FnMut() -> usize,
) -> BenchScenario {
    let mut samples_ns = Vec::with_capacity(iterations);
    let mut output_bytes = 0usize;

    for _ in 0..iterations {
        let started = Instant::now();
        output_bytes = f();
        std::hint::black_box(output_bytes);
        samples_ns.push(elapsed_ns(started.elapsed()));
    }

    BenchScenario {
        id: id.to_owned(),
        group: group.to_owned(),
        iterations,
        median_ns: median(&mut samples_ns),
        mean_ns: mean(&samples_ns),
        output_bytes,
        allocation_bytes: None,
        notes: None,
    }
}

fn benchmark_checked(
    id: &str,
    group: &str,
    iterations: usize,
    mut f: impl FnMut() -> Result<usize>,
) -> Result<BenchScenario> {
    let mut samples_ns = Vec::with_capacity(iterations);
    let mut output_bytes = 0usize;

    for _ in 0..iterations {
        let started = Instant::now();
        output_bytes = f()?;
        std::hint::black_box(output_bytes);
        samples_ns.push(elapsed_ns(started.elapsed()));
    }

    Ok(BenchScenario {
        id: id.to_owned(),
        group: group.to_owned(),
        iterations,
        median_ns: median(&mut samples_ns),
        mean_ns: mean(&samples_ns),
        output_bytes,
        allocation_bytes: None,
        notes: None,
    })
}

fn json_len(value: serde_json::Value) -> usize {
    match serde_json::to_vec(&value) {
        Ok(bytes) => bytes.len(),
        Err(_) => 0,
    }
}

fn sum_file_sizes(paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0usize;
    for path in paths {
        let len = std::fs::metadata(path)?.len();
        total = total.saturating_add(len.min(usize::MAX as u64) as usize);
    }
    Ok(total)
}

fn elapsed_ns(d: Duration) -> u64 {
    d.as_nanos().min(u64::MAX as u128) as u64
}

fn mean(samples: &[u64]) -> u64 {
    let total: u128 = samples.iter().map(|x| *x as u128).sum();
    (total / samples.len() as u128) as u64
}

fn median(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    let mid = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        ((samples[mid - 1] as u128 + samples[mid] as u128) / 2) as u64
    } else {
        samples[mid]
    }
}

pub fn write_summary(path: &Path, summary: &PerfSummary) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(summary)?)?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn required_scenarios_are_covered() -> Result<()> {
        let summary = run_perf_suite()?;
        let ids = summary
            .scenarios
            .iter()
            .map(|s| s.id.as_str())
            .collect::<BTreeSet<_>>();
        for required in REQUIRED_SCENARIO_IDS {
            assert!(
                ids.contains(required),
                "missing required benchmark: {required}"
            );
        }
        Ok(())
    }

    #[test]
    fn summary_serializes_with_schema_version() -> Result<()> {
        let summary = run_perf_suite()?;
        let json = serde_json::to_value(summary)?;
        assert_eq!(json["version"], 1);
        assert!(json["scenarios"].is_array());
        Ok(())
    }
}

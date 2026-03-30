#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
    negative::CorruptPem,
};

pub const REQUIRED_SCENARIO_IDS: &[&str] = &[
    "rsa.fixture.cold",
    "rsa.fixture.warm",
    "ecdsa.fixture.p256",
    "ed25519.fixture",
    "hmac.fixture.hs256",
    "token.fixture.api_key",
    "x509.self_signed",
    "x509.chain",
    "negative.fixture.corrupt_pem",
];

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

pub fn run_perf_suite() -> PerfSummary {
    let scenarios = vec![
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
    ];

    PerfSummary {
        version: 1,
        generated_at_unix: unix_now(),
        scenarios,
    }
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
    fn required_scenarios_are_covered() {
        let summary = run_perf_suite();
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
    }

    #[test]
    fn summary_serializes_with_schema_version() {
        let summary = run_perf_suite();
        let json = serde_json::to_value(summary).expect("serialize summary");
        assert_eq!(json["version"], 1);
        assert!(json["scenarios"].is_array());
    }
}

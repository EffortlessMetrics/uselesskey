#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, Seed, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
    negative::CorruptPem,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<std::alloc::System> = &INSTRUMENTED_SYSTEM;

#[derive(Debug)]
struct Args {
    output: PathBuf,
    iterations: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PerfSummary {
    schema_version: u32,
    iterations: u32,
    scenarios: Vec<ScenarioResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScenarioResult {
    id: String,
    family: String,
    variant: String,
    elapsed_ns_per_iter: u128,
    allocs_per_iter: u64,
    bytes_allocated_per_iter: u64,
    output_size_bytes: usize,
}

fn main() {
    let args = parse_args();
    let summary = run_summary(args.iterations);

    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent).expect("failed to create output parent directory");
    }

    let json = serde_json::to_string_pretty(&summary).expect("serialize perf summary");
    fs::write(&args.output, json).expect("write perf summary");

    println!("wrote {} scenarios to {}", summary.scenarios.len(), args.output.display());
}

fn parse_args() -> Args {
    let mut output = PathBuf::from("target/xtask/perf-summary.json");
    let mut iterations = 6_u32;
    let mut iter = std::env::args().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--output" => {
                let value = iter.next().expect("missing value for --output");
                output = PathBuf::from(value);
            }
            "--iterations" => {
                let value = iter.next().expect("missing value for --iterations");
                iterations = value.parse().expect("invalid integer for --iterations");
            }
            _ => panic!("unknown arg: {arg}; expected --output <path> and/or --iterations <n>"),
        }
    }

    Args { output, iterations }
}

fn run_summary(iterations: u32) -> PerfSummary {
    let mut scenarios = vec![
        bench_rsa_fixture_generation(iterations),
        bench_ecdsa_fixture_generation(iterations),
        bench_ed25519_fixture_generation(iterations),
        bench_hmac_secret_generation(iterations),
        bench_token_generation(iterations),
        bench_x509_self_signed(iterations),
        bench_x509_chain(iterations),
        bench_negative_fixture_generation(iterations),
        bench_rsa_cold_cache(iterations),
        bench_rsa_warm_cache(iterations),
    ];

    scenarios.sort_by(|a, b| a.id.cmp(&b.id));

    PerfSummary {
        schema_version: 1,
        iterations,
        scenarios,
    }
}

fn measure<F>(id: &str, family: &str, variant: &str, iterations: u32, mut f: F) -> ScenarioResult
where
    F: FnMut() -> usize,
{
    let mut output_size_bytes = 0usize;
    let region = Region::new(GLOBAL);
    let start = Instant::now();

    for _ in 0..iterations {
        output_size_bytes = f();
    }

    let elapsed = start.elapsed();
    let delta = region.change();

    ScenarioResult {
        id: id.to_string(),
        family: family.to_string(),
        variant: variant.to_string(),
        elapsed_ns_per_iter: elapsed.as_nanos() / u128::from(iterations),
        allocs_per_iter: (delta.allocations / iterations as usize) as u64,
        bytes_allocated_per_iter: (delta.bytes_allocated / iterations as usize) as u64,
        output_size_bytes,
    }
}

fn deterministic_factory() -> Factory {
    let seed = Seed::from_env_value("perf-summary-seed").expect("valid seed");
    Factory::deterministic(seed)
}

fn bench_rsa_fixture_generation(iterations: u32) -> ScenarioResult {
    measure(
        "rsa_fixture_generation",
        "rsa",
        "deterministic",
        iterations,
        || {
            let fx = deterministic_factory();
            let kp = fx.rsa("perf-rsa", RsaSpec::rs256());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        },
    )
}

fn bench_ecdsa_fixture_generation(iterations: u32) -> ScenarioResult {
    measure(
        "ecdsa_fixture_generation",
        "ecdsa",
        "deterministic",
        iterations,
        || {
            let fx = deterministic_factory();
            let kp = fx.ecdsa("perf-ecdsa", EcdsaSpec::es256());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        },
    )
}

fn bench_ed25519_fixture_generation(iterations: u32) -> ScenarioResult {
    measure(
        "ed25519_fixture_generation",
        "ed25519",
        "deterministic",
        iterations,
        || {
            let fx = deterministic_factory();
            let kp = fx.ed25519("perf-ed25519", Ed25519Spec::new());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        },
    )
}

fn bench_hmac_secret_generation(iterations: u32) -> ScenarioResult {
    measure(
        "hmac_secret_generation",
        "hmac",
        "deterministic",
        iterations,
        || {
            let fx = deterministic_factory();
            let secret = fx.hmac("perf-hmac", HmacSpec::hs256());
            secret.secret_bytes().len()
        },
    )
}

fn bench_token_generation(iterations: u32) -> ScenarioResult {
    measure(
        "token_generation",
        "token",
        "deterministic",
        iterations,
        || {
            let fx = deterministic_factory();
            let tok = fx.token("perf-token", TokenSpec::oauth_access_token());
            tok.value().len()
        },
    )
}

fn bench_x509_self_signed(iterations: u32) -> ScenarioResult {
    measure(
        "x509_self_signed",
        "x509",
        "self_signed",
        iterations,
        || {
            let fx = deterministic_factory();
            let cert = fx.x509_self_signed("perf-x509-self", X509Spec::self_signed("perf.example.com"));
            cert.cert_der().len() + cert.private_key_pkcs8_der().len()
        },
    )
}

fn bench_x509_chain(iterations: u32) -> ScenarioResult {
    measure(
        "x509_chain",
        "x509",
        "chain",
        iterations,
        || {
            let fx = deterministic_factory();
            let chain = fx.x509_chain("perf-x509-chain", ChainSpec::new("chain.perf.example.com"));
            chain.chain_pem().len() + chain.leaf_private_key_pkcs8_der().len()
        },
    )
}

fn bench_negative_fixture_generation(iterations: u32) -> ScenarioResult {
    let fx = deterministic_factory();
    let keypair = fx.rsa("perf-negative", RsaSpec::rs256());
    measure(
        "negative_fixture_generation",
        "negative",
        "rsa_corrupt_and_mismatch",
        iterations,
        || {
            let corrupt = keypair.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
            let mismatch = keypair.mismatched_public_key_spki_der();
            corrupt.len() + mismatch.len()
        },
    )
}

fn bench_rsa_cold_cache(iterations: u32) -> ScenarioResult {
    measure(
        "rsa_cold_cache",
        "cache",
        "cold",
        iterations,
        || {
            let fx = deterministic_factory();
            let kp = fx.rsa("perf-cache", RsaSpec::rs256());
            kp.private_key_pkcs8_der().len()
        },
    )
}

fn bench_rsa_warm_cache(iterations: u32) -> ScenarioResult {
    let fx = deterministic_factory();
    let primed = fx.rsa("perf-cache", RsaSpec::rs256());
    let output_size = primed.private_key_pkcs8_der().len();

    measure(
        "rsa_warm_cache",
        "cache",
        "warm",
        iterations,
        || {
            let _ = fx.rsa("perf-cache", RsaSpec::rs256());
            output_size
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_smoke_has_all_required_scenarios() {
        let summary = run_summary(1);
        let ids: std::collections::BTreeSet<_> =
            summary.scenarios.iter().map(|s| s.id.as_str()).collect();

        let required = [
            "rsa_fixture_generation",
            "ecdsa_fixture_generation",
            "ed25519_fixture_generation",
            "hmac_secret_generation",
            "token_generation",
            "x509_self_signed",
            "x509_chain",
            "negative_fixture_generation",
            "rsa_cold_cache",
            "rsa_warm_cache",
        ];

        for id in required {
            assert!(ids.contains(id), "missing benchmark scenario: {id}");
        }
    }
}

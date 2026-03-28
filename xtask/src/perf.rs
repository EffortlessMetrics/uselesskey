use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uselesskey::negative::CorruptPem;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory,
    HmacFactoryExt, HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
    X509Spec,
};

const PERF_BASELINE_RELATIVE_PATH: &str = "docs/metadata/perf-baselines.json";
const PERF_SUMMARY_RELATIVE_PATH: &str = "target/xtask/perf-summary.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfSummary {
    pub schema_version: u32,
    pub iterations: u32,
    pub benchmark_count: usize,
    pub generated_at_utc: String,
    pub results: Vec<PerfResult>,
    pub speedups: Vec<CacheSpeedup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfResult {
    pub id: String,
    pub family: String,
    pub variant: String,
    pub mean_wall_time_ns: u128,
    pub median_wall_time_ns: u128,
    pub min_wall_time_ns: u128,
    pub max_wall_time_ns: u128,
    pub output_bytes: usize,
    pub allocated_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSpeedup {
    pub family: String,
    pub cold_id: String,
    pub warm_id: String,
    pub speedup_ratio: f64,
}

#[derive(Debug, Clone, Deserialize)]
struct PerfBaseline {
    schema_version: u32,
    benchmarks: Vec<PerfBudget>,
}

#[derive(Debug, Clone, Deserialize)]
struct PerfBudget {
    id: String,
    baseline_mean_ns: u128,
    max_regression_percent: f64,
    fail_on_regression: bool,
    note: Option<String>,
}

pub fn run(compare: bool, iterations: u32) -> Result<()> {
    let summary = run_summary(iterations.max(1));
    write_summary(&summary)?;

    if compare {
        validate_baseline_file()?;
        compare_with_baseline(&summary)?;
    }

    Ok(())
}

fn run_summary(iterations: u32) -> PerfSummary {
    let mut results = Vec::new();

    let rsa_cold = measure_case("rsa/cold", "rsa", "cold-cache", iterations, || {
        let fx = Factory::random();
        let rsa = fx.rsa("perf-rsa", RsaSpec::rs256());
        rsa.private_key_pkcs8_der().len() + rsa.public_key_spki_der().len()
    });
    let rsa_warm = measure_case_timed("rsa/warm", "rsa", "warm-cache", iterations, || {
        let fx = Factory::random();
        let _ = fx.rsa("perf-rsa", RsaSpec::rs256());
        let start = Instant::now();
        let rsa = fx.rsa("perf-rsa", RsaSpec::rs256());
        let elapsed = start.elapsed();
        (
            elapsed,
            rsa.private_key_pkcs8_der().len() + rsa.public_key_spki_der().len(),
        )
    });
    results.push(rsa_cold);
    results.push(rsa_warm);

    results.push(measure_case(
        "ecdsa/cold",
        "ecdsa",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let kp = fx.ecdsa("perf-ecdsa", EcdsaSpec::es256());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        },
    ));

    results.push(measure_case(
        "ed25519/cold",
        "ed25519",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let kp = fx.ed25519("perf-ed25519", Ed25519Spec::new());
            kp.private_key_pkcs8_der().len() + kp.public_key_spki_der().len()
        },
    ));

    results.push(measure_case(
        "hmac/cold",
        "hmac",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let secret = fx.hmac("perf-hmac", HmacSpec::hs512());
            secret.secret_bytes().len()
        },
    ));

    results.push(measure_case(
        "token/cold",
        "token",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let token = fx.token("perf-token", TokenSpec::oauth_access_token());
            token.value().len()
        },
    ));

    results.push(measure_case(
        "x509/self-signed/cold",
        "x509-self-signed",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let cert = fx.x509_self_signed("perf-cert", X509Spec::self_signed("perf.example.com"));
            cert.cert_der().len() + cert.private_key_pkcs8_der().len()
        },
    ));

    results.push(measure_case(
        "x509/chain/cold",
        "x509-chain",
        "cold-cache",
        iterations,
        || {
            let fx = Factory::random();
            let chain = fx.x509_chain("perf-chain", ChainSpec::new("perf.example.com"));
            chain.leaf_cert_der().len()
                + chain.intermediate_cert_der().len()
                + chain.root_cert_der().len()
                + chain.leaf_private_key_pkcs8_der().len()
        },
    ));

    results.push(measure_case(
        "negative/rsa-corrupt-pem",
        "negative-fixture",
        "corrupt-pem",
        iterations,
        || {
            let fx = Factory::random();
            let rsa = fx.rsa("perf-negative", RsaSpec::rs256());
            rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64).len()
        },
    ));

    let speedups = compute_speedups(&results);

    PerfSummary {
        schema_version: 1,
        iterations,
        benchmark_count: results.len(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        results,
        speedups,
    }
}

fn measure_case<F>(
    id: &str,
    family: &str,
    variant: &str,
    iterations: u32,
    mut run_once: F,
) -> PerfResult
where
    F: FnMut() -> usize,
{
    let mut samples_ns = Vec::with_capacity(iterations as usize);
    let mut last_output_size = 0;

    for _ in 0..iterations {
        let start = Instant::now();
        last_output_size = run_once();
        samples_ns.push(start.elapsed().as_nanos());
    }

    stats(id, family, variant, &samples_ns, last_output_size)
}

fn measure_case_timed<F>(
    id: &str,
    family: &str,
    variant: &str,
    iterations: u32,
    mut run_once: F,
) -> PerfResult
where
    F: FnMut() -> (std::time::Duration, usize),
{
    let mut samples_ns = Vec::with_capacity(iterations as usize);
    let mut last_output_size = 0;

    for _ in 0..iterations {
        let (elapsed, output_size) = run_once();
        last_output_size = output_size;
        samples_ns.push(elapsed.as_nanos());
    }

    stats(id, family, variant, &samples_ns, last_output_size)
}

fn stats(
    id: &str,
    family: &str,
    variant: &str,
    samples_ns: &[u128],
    output_bytes: usize,
) -> PerfResult {
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable();

    let sum: u128 = sorted.iter().sum();
    let len = sorted.len() as u128;
    let mean_wall_time_ns = sum / len;
    let median_wall_time_ns = sorted[sorted.len() / 2];
    let min_wall_time_ns = sorted[0];
    let max_wall_time_ns = sorted[sorted.len() - 1];

    PerfResult {
        id: id.to_string(),
        family: family.to_string(),
        variant: variant.to_string(),
        mean_wall_time_ns,
        median_wall_time_ns,
        min_wall_time_ns,
        max_wall_time_ns,
        output_bytes,
        allocated_bytes: None,
    }
}

fn compute_speedups(results: &[PerfResult]) -> Vec<CacheSpeedup> {
    let mut by_id = BTreeMap::new();
    for result in results {
        by_id.insert(result.id.as_str(), result);
    }

    let pairs = [("rsa", "rsa/cold", "rsa/warm")];

    pairs
        .into_iter()
        .filter_map(|(family, cold_id, warm_id)| {
            let cold = by_id.get(cold_id)?;
            let warm = by_id.get(warm_id)?;
            if warm.mean_wall_time_ns == 0 {
                return None;
            }
            Some(CacheSpeedup {
                family: family.to_string(),
                cold_id: cold_id.to_string(),
                warm_id: warm_id.to_string(),
                speedup_ratio: cold.mean_wall_time_ns as f64 / warm.mean_wall_time_ns as f64,
            })
        })
        .collect()
}

fn write_summary(summary: &PerfSummary) -> Result<()> {
    let path_buf = workspace_root().join(PERF_SUMMARY_RELATIVE_PATH);
    let path = path_buf.as_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create perf output dir {:?}", parent))?;
    }
    let json = serde_json::to_string_pretty(summary).context("failed to serialize perf summary")?;
    fs::write(path, json).with_context(|| {
        format!(
            "failed to write perf summary to {}",
            path.display()
        )
    })?;
    Ok(())
}

fn compare_with_baseline(summary: &PerfSummary) -> Result<()> {
    let baseline_path = workspace_root().join(PERF_BASELINE_RELATIVE_PATH);
    let baseline_raw = fs::read_to_string(&baseline_path)
        .with_context(|| format!("failed to read {}", baseline_path.display()))?;
    let baseline: PerfBaseline =
        serde_json::from_str(&baseline_raw).context("failed to parse perf baseline JSON")?;

    if baseline.schema_version != 1 {
        bail!(
            "unsupported perf baseline schema version: {}",
            baseline.schema_version
        );
    }

    let observed: BTreeMap<&str, &PerfResult> = summary
        .results
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();

    let mut failures = Vec::new();
    for budget in &baseline.benchmarks {
        let Some(observed_entry) = observed.get(budget.id.as_str()) else {
            if budget.fail_on_regression {
                failures.push(format!(
                    "{}: missing benchmark result{}",
                    budget.id,
                    budget
                        .note
                        .as_deref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
            continue;
        };

        let threshold = 1.0 + (budget.max_regression_percent / 100.0);
        let baseline_mean = budget.baseline_mean_ns;
        let allowed_max = (baseline_mean as f64 * threshold).round() as u128;
        if observed_entry.mean_wall_time_ns > allowed_max && budget.fail_on_regression {
            failures.push(format!(
                "{} regressed: observed={}ns baseline={}ns allowed={}ns ({}%)",
                budget.id,
                observed_entry.mean_wall_time_ns,
                baseline_mean,
                allowed_max,
                budget.max_regression_percent
            ));
        }
    }

    if !failures.is_empty() {
        bail!("performance budget check failed:\n{}", failures.join("\n"));
    }

    Ok(())
}

pub fn validate_baseline_file() -> Result<()> {
    let baseline_path = workspace_root().join(PERF_BASELINE_RELATIVE_PATH);
    let baseline_raw = fs::read_to_string(&baseline_path)
        .with_context(|| format!("failed to read {}", baseline_path.display()))?;
    let baseline: PerfBaseline =
        serde_json::from_str(&baseline_raw).context("failed to parse perf baseline JSON")?;

    if baseline.schema_version != 1 {
        bail!("perf baseline schema_version must be 1");
    }

    let mut seen = BTreeSet::new();
    for entry in &baseline.benchmarks {
        if entry.id.trim().is_empty() {
            bail!("perf baseline entry id cannot be empty");
        }
        if !seen.insert(entry.id.clone()) {
            bail!("duplicate perf baseline id: {}", entry.id);
        }
        if entry.max_regression_percent < 0.0 {
            bail!(
                "max_regression_percent cannot be negative for {}",
                entry.id
            );
        }
        if entry.baseline_mean_ns == 0 {
            bail!("baseline_mean_ns must be > 0 for {}", entry.id);
        }
    }

    assert_no_missing_core_families(&baseline)
}

fn assert_no_missing_core_families(baseline: &PerfBaseline) -> Result<()> {
    let expected = [
        "rsa/cold",
        "rsa/warm",
        "ecdsa/cold",
        "ed25519/cold",
        "hmac/cold",
        "token/cold",
        "x509/self-signed/cold",
        "x509/chain/cold",
        "negative/rsa-corrupt-pem",
    ];

    let present: BTreeSet<&str> = baseline.benchmarks.iter().map(|e| e.id.as_str()).collect();
    let missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|id| !present.contains(id))
        .collect();

    if !missing.is_empty() {
        bail!("perf baseline missing benchmark ids: {}", missing.join(", "));
    }

    Ok(())
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new(env!("CARGO_MANIFEST_DIR")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_is_valid_and_complete() {
        validate_baseline_file().expect("perf baseline should validate");
    }

    #[test]
    fn smoke_run_summary_has_all_expected_benchmarks() {
        let summary = run_summary(1);
        let ids: BTreeSet<&str> = summary.results.iter().map(|r| r.id.as_str()).collect();
        for required in [
            "rsa/cold",
            "rsa/warm",
            "ecdsa/cold",
            "ed25519/cold",
            "hmac/cold",
            "token/cold",
            "x509/self-signed/cold",
            "x509/chain/cold",
            "negative/rsa-corrupt-pem",
        ] {
            assert!(ids.contains(required), "missing benchmark id: {required}");
        }
    }
}

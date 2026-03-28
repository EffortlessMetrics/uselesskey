#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uselesskey::negative::CorruptPem;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
};

pub const REQUIRED_BENCH_IDS: &[&str] = &[
    "rsa.generate.cold",
    "rsa.generate.warm",
    "ecdsa.generate.cold",
    "ecdsa.generate.warm",
    "ed25519.generate.cold",
    "ed25519.generate.warm",
    "hmac.generate.cold",
    "hmac.generate.warm",
    "token.generate.cold",
    "token.generate.warm",
    "x509.self_signed.cold",
    "x509.self_signed.warm",
    "x509.chain.cold",
    "x509.chain.warm",
    "negative.generate.cold",
    "negative.generate.warm",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfEntry {
    pub id: String,
    pub family: String,
    pub variant: String,
    pub iterations: u32,
    pub total_ns: u128,
    pub mean_ns: u128,
    pub output_bytes: usize,
    pub allocations_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfReport {
    pub schema_version: u32,
    pub generated_at_unix_s: u64,
    pub host: String,
    pub entries: Vec<PerfEntry>,
    pub cache_hit_speedups: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBaseline {
    pub schema_version: u32,
    pub generated_at: String,
    pub budgets: Vec<PerfBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudget {
    pub id: String,
    pub baseline_mean_ns: u128,
    pub max_regression_pct: f64,
    pub fail_in_ci: bool,
    pub note: String,
}

pub fn run_report(iterations: u32) -> PerfReport {
    let mut entries = Vec::new();

    entries.push(bench_family("rsa.generate", iterations, cold_rsa, warm_rsa));
    entries.push(bench_family(
        "ecdsa.generate",
        iterations,
        cold_ecdsa,
        warm_ecdsa,
    ));
    entries.push(bench_family(
        "ed25519.generate",
        iterations,
        cold_ed25519,
        warm_ed25519,
    ));
    entries.push(bench_family(
        "hmac.generate",
        iterations,
        cold_hmac,
        warm_hmac,
    ));
    entries.push(bench_family(
        "token.generate",
        iterations,
        cold_token,
        warm_token,
    ));
    entries.push(bench_family(
        "x509.self_signed",
        iterations,
        cold_x509_self_signed,
        warm_x509_self_signed,
    ));
    entries.push(bench_family(
        "x509.chain",
        iterations,
        cold_x509_chain,
        warm_x509_chain,
    ));
    entries.push(bench_family(
        "negative.generate",
        iterations,
        cold_negative,
        warm_negative,
    ));

    let entries: Vec<PerfEntry> = entries.into_iter().flatten().collect();
    let cache_hit_speedups = compute_cache_speedups(&entries);

    PerfReport {
        schema_version: 1,
        generated_at_unix_s: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        host: std::env::consts::OS.to_string(),
        entries,
        cache_hit_speedups,
    }
}

fn bench_family(
    family: &'static str,
    iterations: u32,
    cold: impl Fn() -> usize,
    warm: impl Fn() -> usize,
) -> [PerfEntry; 2] {
    let cold = measure(cold, iterations, format!("{family}.cold"), family, "cold");
    let warm = measure(warm, iterations, format!("{family}.warm"), family, "warm");
    [cold, warm]
}

fn measure(
    mut f: impl FnMut() -> usize,
    iterations: u32,
    id: String,
    family: &str,
    variant: &str,
) -> PerfEntry {
    if variant == "warm" {
        let _ = f();
    }
    let started = Instant::now();
    let mut last_output = 0usize;

    for _ in 0..iterations {
        last_output = f();
    }

    let total_ns = started.elapsed().as_nanos();
    let mean_ns = total_ns / u128::from(iterations);

    PerfEntry {
        id,
        family: family.to_string(),
        variant: variant.to_string(),
        iterations,
        total_ns,
        mean_ns,
        output_bytes: last_output,
        allocations_bytes: None,
    }
}

fn compute_cache_speedups(entries: &[PerfEntry]) -> BTreeMap<String, f64> {
    let mut by_family = BTreeMap::<&str, (&PerfEntry, &PerfEntry)>::new();
    for entry in entries {
        let slot = by_family
            .entry(&entry.family)
            .or_insert_with(|| (entry, entry));
        if entry.variant == "cold" {
            slot.0 = entry;
        } else if entry.variant == "warm" {
            slot.1 = entry;
        }
    }

    by_family
        .into_iter()
        .filter_map(|(family, (cold, warm))| {
            if warm.mean_ns == 0 || cold.mean_ns == 0 {
                return None;
            }
            let speedup = (cold.mean_ns as f64) / (warm.mean_ns as f64);
            Some((family.to_string(), speedup))
        })
        .collect()
}

pub fn validate_coverage(report: &PerfReport) -> Result<()> {
    let ids = report
        .entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<BTreeSet<_>>();

    let missing = REQUIRED_BENCH_IDS
        .iter()
        .copied()
        .filter(|id| !ids.contains(id))
        .collect::<Vec<_>>();

    if !missing.is_empty() {
        bail!("missing benchmark IDs: {}", missing.join(", "));
    }
    Ok(())
}

pub fn load_baseline(path: &Path) -> Result<PerfBaseline> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline file: {}", path.display()))?;
    let baseline: PerfBaseline = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse baseline JSON: {}", path.display()))?;
    Ok(baseline)
}

pub fn compare_to_baseline(
    report: &PerfReport,
    baseline: &PerfBaseline,
    fail_on_ci: bool,
) -> Result<()> {
    let report_by_id = report
        .entries
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    for budget in &baseline.budgets {
        let Some(entry) = report_by_id.get(budget.id.as_str()) else {
            bail!("benchmark missing from report: {}", budget.id);
        };

        let max_allowed =
            (budget.baseline_mean_ns as f64) * (1.0 + budget.max_regression_pct / 100.0);
        if (entry.mean_ns as f64) > max_allowed && (!fail_on_ci || budget.fail_in_ci) {
            bail!(
                "budget regression on {}: mean={}ns baseline={}ns tolerance={}%, note={}",
                budget.id,
                entry.mean_ns,
                budget.baseline_mean_ns,
                budget.max_regression_pct,
                budget.note
            );
        }
    }

    Ok(())
}

fn cold_rsa() -> usize {
    let fx = Factory::random();
    fx.rsa("bench-rsa", RsaSpec::rs256())
        .private_key_pkcs8_der()
        .len()
}

fn warm_rsa() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.rsa("bench-rsa", RsaSpec::rs256());
        fx
    });
    fx.rsa("bench-rsa", RsaSpec::rs256())
        .private_key_pkcs8_der()
        .len()
}

fn cold_ecdsa() -> usize {
    let fx = Factory::random();
    fx.ecdsa("bench-ecdsa", EcdsaSpec::es256())
        .private_key_pkcs8_der()
        .len()
}

fn warm_ecdsa() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.ecdsa("bench-ecdsa", EcdsaSpec::es256());
        fx
    });
    fx.ecdsa("bench-ecdsa", EcdsaSpec::es256())
        .private_key_pkcs8_der()
        .len()
}

fn cold_ed25519() -> usize {
    let fx = Factory::random();
    fx.ed25519("bench-ed25519", Ed25519Spec::new())
        .private_key_pkcs8_der()
        .len()
}

fn warm_ed25519() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.ed25519("bench-ed25519", Ed25519Spec::new());
        fx
    });
    fx.ed25519("bench-ed25519", Ed25519Spec::new())
        .private_key_pkcs8_der()
        .len()
}

fn cold_hmac() -> usize {
    let fx = Factory::random();
    fx.hmac("bench-hmac", HmacSpec::hs256())
        .secret_bytes()
        .len()
}

fn warm_hmac() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.hmac("bench-hmac", HmacSpec::hs256());
        fx
    });
    fx.hmac("bench-hmac", HmacSpec::hs256())
        .secret_bytes()
        .len()
}

fn cold_token() -> usize {
    let fx = Factory::random();
    fx.token("bench-token", TokenSpec::api_key()).value().len()
}

fn warm_token() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.token("bench-token", TokenSpec::api_key());
        fx
    });
    fx.token("bench-token", TokenSpec::api_key()).value().len()
}

fn cold_x509_self_signed() -> usize {
    let fx = Factory::random();
    fx.x509_self_signed("bench-self", X509Spec::self_signed("bench.example.com"))
        .cert_der()
        .len()
}

fn warm_x509_self_signed() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.x509_self_signed("bench-self", X509Spec::self_signed("bench.example.com"));
        fx
    });
    fx.x509_self_signed("bench-self", X509Spec::self_signed("bench.example.com"))
        .cert_der()
        .len()
}

fn cold_x509_chain() -> usize {
    let fx = Factory::random();
    let chain = fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com"));
    chain.leaf_cert_der().len() + chain.intermediate_cert_der().len() + chain.root_cert_der().len()
}

fn warm_x509_chain() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| {
        let fx = Factory::random();
        let _ = fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com"));
        fx
    });
    let chain = fx.x509_chain("bench-chain", ChainSpec::new("bench.example.com"));
    chain.leaf_cert_der().len() + chain.intermediate_cert_der().len() + chain.root_cert_der().len()
}

fn cold_negative() -> usize {
    let fx = Factory::random();
    let kp = fx.rsa("bench-negative", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    bad.len()
}

fn warm_negative() -> usize {
    static FX: OnceLock<Factory> = OnceLock::new();
    let fx = FX.get_or_init(|| Factory::random());
    let kp = fx.rsa("bench-negative", RsaSpec::rs256());
    kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64)
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_has_required_coverage() {
        let report = run_report(1);
        validate_coverage(&report).expect("required benchmark IDs should be present");
    }
}

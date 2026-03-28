#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, serde::Deserialize)]
struct PerfBaseline {
    schema_version: u32,
    paths: Vec<PerfBaselinePath>,
}

#[derive(Debug, serde::Deserialize)]
struct PerfBaselinePath {
    id: String,
    baseline_elapsed_ns_per_iter: u128,
    max_regression_pct: f64,
    enforce_in_ci: bool,
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/metadata/perf-baselines.json")
        .canonicalize()
        .expect("baseline file path should resolve")
}

fn read_baseline() -> PerfBaseline {
    let path = baseline_path();
    let json = fs::read_to_string(path).expect("read baseline json");
    serde_json::from_str(&json).expect("parse baseline json")
}

#[test]
fn perf_baseline_schema_is_valid() {
    let baseline = read_baseline();
    assert_eq!(baseline.schema_version, 1);
    assert!(!baseline.paths.is_empty(), "baseline must contain paths");

    for path in baseline.paths {
        assert!(!path.id.is_empty(), "path id must not be empty");
        assert!(
            path.baseline_elapsed_ns_per_iter > 0,
            "baseline elapsed must be > 0"
        );
        assert!(path.max_regression_pct >= 0.0, "threshold must be non-negative");
        if path.enforce_in_ci {
            assert!(
                path.max_regression_pct <= 20.0,
                "enforced paths should be strict enough"
            );
        }
    }
}

#[test]
fn perf_baseline_covers_required_fixture_families() {
    let baseline = read_baseline();
    let ids: BTreeSet<_> = baseline.paths.into_iter().map(|p| p.id).collect();

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

    for required_id in required {
        assert!(
            ids.contains(required_id),
            "missing perf baseline entry: {required_id}"
        );
    }
}

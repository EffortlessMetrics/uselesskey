use std::path::Path;

use uselesskey_bench::{REQUIRED_BENCH_IDS, load_baseline, run_report, validate_coverage};

#[test]
fn baseline_schema_is_valid_and_complete() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/metadata/perf-baselines.json");
    let baseline = load_baseline(&path).expect("baseline should parse");
    assert_eq!(
        baseline.schema_version, 1,
        "schema version should be stable"
    );

    let ids = baseline
        .budgets
        .iter()
        .map(|budget| budget.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for required in REQUIRED_BENCH_IDS {
        assert!(
            ids.contains(required),
            "missing budget for benchmark id: {required}"
        );
    }
}

#[test]
fn smoke_report_is_machine_readable_and_complete() {
    let report = run_report(1);
    validate_coverage(&report).expect("report should include all required benchmark IDs");

    let encoded = serde_json::to_string(&report).expect("report should serialize");
    let decoded: uselesskey_bench::PerfReport =
        serde_json::from_str(&encoded).expect("report should deserialize");

    assert_eq!(report.entries.len(), decoded.entries.len());
}

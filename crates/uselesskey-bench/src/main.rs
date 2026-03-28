#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use uselesskey_bench::{compare_to_baseline, load_baseline, run_report, validate_coverage};

fn main() -> Result<()> {
    let mut output = PathBuf::from("target/perf/perf-summary.json");
    let mut baseline_path = PathBuf::from("docs/metadata/perf-baselines.json");
    let mut compare = false;
    let mut fail_on_ci = false;
    let mut iterations = 3u32;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                output = PathBuf::from(args.next().context("missing value for --output")?);
            }
            "--baseline" => {
                baseline_path = PathBuf::from(args.next().context("missing value for --baseline")?);
            }
            "--compare" => compare = true,
            "--fail-on-ci" => fail_on_ci = true,
            "--iterations" => {
                let raw = args.next().context("missing value for --iterations")?;
                iterations = raw
                    .parse()
                    .with_context(|| format!("invalid --iterations value: {raw}"))?;
            }
            other => anyhow::bail!("unknown arg: {other}"),
        }
    }

    let report = run_report(iterations);
    validate_coverage(&report)?;

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory: {}", parent.display()))?;
    }

    let payload = serde_json::to_string_pretty(&report).context("failed to serialize report")?;
    std::fs::write(&output, payload)
        .with_context(|| format!("failed to write report: {}", output.display()))?;

    if compare {
        let baseline = load_baseline(&baseline_path)?;
        compare_to_baseline(&report, &baseline, fail_on_ci)?;
    }

    println!("perf report written to {}", output.display());
    Ok(())
}

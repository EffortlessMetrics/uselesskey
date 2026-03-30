#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use uselesskey_bench::{run_perf_suite, write_summary};

#[derive(Parser, Debug)]
#[command(
    name = "uselesskey-bench",
    about = "Run machine-readable fixture performance benchmarks."
)]
struct Cli {
    /// Output file for benchmark JSON summary.
    #[arg(long, default_value = "target/xtask/perf/latest.json")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let summary = run_perf_suite();
    write_summary(&cli.output, &summary)?;
    eprintln!("wrote perf summary: {}", cli.output.display());
    Ok(())
}

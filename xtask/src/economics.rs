use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Serialize;

const ECONOMICS_JSON_PATH: &str = "target/xtask/economics/latest.json";
const ECONOMICS_MARKDOWN_PATH: &str = "target/xtask/economics/latest.md";
const ECONOMICS_DOCS_PATH: &str = "docs/reference/dependency-economics.md";

struct Lane {
    use_case: &'static str,
    recommended_lane: &'static str,
    package: &'static str,
    check_args: &'static [&'static str],
    smoke_args: Option<&'static [&'static str]>,
}

const LANES: &[Lane] = &[
    Lane {
        use_case: "entropy-only",
        recommended_lane: "uselesskey-entropy",
        package: "uselesskey-entropy",
        check_args: &["check", "-p", "uselesskey-entropy"],
        smoke_args: Some(&["test", "-p", "uselesskey-entropy"]),
    },
    Lane {
        use_case: "token-shape-only",
        recommended_lane: "uselesskey-token",
        package: "uselesskey-token",
        check_args: &["check", "-p", "uselesskey-token"],
        smoke_args: Some(&["test", "-p", "uselesskey-token", "--lib"]),
    },
    Lane {
        use_case: "runtime-rsa",
        recommended_lane: "uselesskey-rsa",
        package: "uselesskey-rsa",
        check_args: &["check", "-p", "uselesskey-rsa"],
        smoke_args: Some(&["test", "-p", "uselesskey-rsa", "--lib"]),
    },
    Lane {
        use_case: "build-time-shape-fixtures",
        recommended_lane: "uselesskey-cli materialize (shape-only)",
        package: "materialize-shape-buildrs-example",
        check_args: &["check", "-p", "materialize-shape-buildrs-example"],
        smoke_args: Some(&["test", "-p", "materialize-shape-buildrs-example"]),
    },
    Lane {
        use_case: "build-time-rsa-fixtures",
        recommended_lane: "uselesskey-cli materialize (rsa)",
        package: "materialize-buildrs-example",
        check_args: &["check", "-p", "materialize-buildrs-example"],
        smoke_args: Some(&["test", "-p", "materialize-buildrs-example"]),
    },
];

#[derive(Debug, Serialize)]
struct EconomicsReport {
    schema_version: u32,
    entries: Vec<EconomicsEntry>,
}

#[derive(Debug, Serialize)]
struct EconomicsEntry {
    use_case: String,
    recommended_lane: String,
    package: String,
    dependency_count: usize,
    first_check_ms: u64,
    repeat_check_ms: u64,
    check_status: String,
    smoke_status: String,
    check_command: String,
    smoke_command: Option<String>,
    details: Option<String>,
}

#[derive(Debug)]
struct CommandRun {
    command: String,
    status: String,
    duration_ms: u64,
    details: Option<String>,
}

pub fn economics_cmd() -> Result<()> {
    let mut entries = Vec::with_capacity(LANES.len());
    let mut failed = false;

    for lane in LANES {
        eprintln!("==> economics {}", lane.use_case);
        let dependency_count = dependency_count(lane.package)?;
        let first = run_cargo(lane.check_args)?;
        let repeat = run_cargo(lane.check_args)?;
        let smoke = match lane.smoke_args {
            Some(args) => Some(run_cargo(args)?),
            None => None,
        };

        if first.status != "ok" || repeat.status != "ok" {
            failed = true;
        }
        if let Some(smoke) = &smoke
            && smoke.status != "ok"
        {
            failed = true;
        }

        let mut details = Vec::new();
        if let Some(detail) = &first.details {
            details.push(format!("first-check: {detail}"));
        }
        if let Some(detail) = &repeat.details {
            details.push(format!("repeat-check: {detail}"));
        }
        if let Some(smoke) = &smoke
            && let Some(detail) = &smoke.details
        {
            details.push(format!("smoke: {detail}"));
        }

        entries.push(EconomicsEntry {
            use_case: lane.use_case.to_string(),
            recommended_lane: lane.recommended_lane.to_string(),
            package: lane.package.to_string(),
            dependency_count,
            first_check_ms: first.duration_ms,
            repeat_check_ms: repeat.duration_ms,
            check_status: aggregate_status(&[&first.status, &repeat.status]).to_string(),
            smoke_status: smoke
                .as_ref()
                .map(|run| run.status.clone())
                .unwrap_or_else(|| "n/a".to_string()),
            check_command: first.command,
            smoke_command: smoke.as_ref().map(|run| run.command.clone()),
            details: if details.is_empty() {
                None
            } else {
                Some(details.join(" | "))
            },
        });
    }

    let report = EconomicsReport {
        schema_version: 1,
        entries,
    };
    write_json_report(Path::new(ECONOMICS_JSON_PATH), &report)?;
    write_markdown_report(
        Path::new(ECONOMICS_MARKDOWN_PATH),
        render_table_markdown(&report),
    )?;
    write_markdown_report(
        Path::new(ECONOMICS_DOCS_PATH),
        render_docs_markdown(&report),
    )?;

    println!(
        "economics: wrote {} and {}",
        ECONOMICS_JSON_PATH, ECONOMICS_MARKDOWN_PATH
    );

    if failed {
        bail!("one or more economics lane checks failed")
    }

    Ok(())
}

fn dependency_count(package: &str) -> Result<usize> {
    let output = Command::new("cargo")
        .args(["tree", "-p", package, "--prefix", "none"])
        .output()
        .with_context(|| format!("failed to run cargo tree for {package}"))?;
    if !output.status.success() {
        bail!(
            "cargo tree -p {package} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_package_names(&stdout).len())
}

fn parse_package_names(tree: &str) -> BTreeSet<String> {
    tree.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect()
}

fn run_cargo(args: &[&str]) -> Result<CommandRun> {
    let command = format!("cargo {}", args.join(" "));
    let start = Instant::now();
    let output = Command::new("cargo")
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{command}`"))?;
    let duration_ms = start.elapsed().as_millis() as u64;

    let status = if output.status.success() {
        "ok"
    } else {
        "failed"
    };
    let details = if output.status.success() {
        None
    } else {
        Some(trim_command_output(&output.stderr, &output.stdout))
    };

    Ok(CommandRun {
        command,
        status: status.to_string(),
        duration_ms,
        details,
    })
}

fn trim_command_output(stderr: &[u8], stdout: &[u8]) -> String {
    let stderr_text = String::from_utf8_lossy(stderr).trim().to_string();
    if !stderr_text.is_empty() {
        return stderr_text.lines().take(6).collect::<Vec<_>>().join(" ");
    }

    String::from_utf8_lossy(stdout)
        .trim()
        .lines()
        .take(6)
        .collect::<Vec<_>>()
        .join(" ")
}

fn aggregate_status(statuses: &[&str]) -> &'static str {
    if statuses.iter().all(|status| *status == "ok") {
        "ok"
    } else {
        "failed"
    }
}

fn render_table_markdown(report: &EconomicsReport) -> String {
    let mut out = String::from(
        "| use case | recommended lane | dep count | first check | repeat check | smoke |\n",
    );
    out.push_str("| --- | --- | ---: | ---: | ---: | --- |\n");
    for entry in &report.entries {
        out.push_str(&format!(
            "| {} | {} | {} | {:.2}s | {:.2}s | {} |\n",
            entry.use_case,
            entry.recommended_lane,
            entry.dependency_count,
            entry.first_check_ms as f64 / 1000.0,
            entry.repeat_check_ms as f64 / 1000.0,
            entry.smoke_status
        ));
    }
    out
}

fn render_docs_table_markdown(report: &EconomicsReport) -> String {
    let mut out = String::from("| use case | recommended lane | dep count | smoke |\n");
    out.push_str("| --- | --- | ---: | --- |\n");
    for entry in &report.entries {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            entry.use_case, entry.recommended_lane, entry.dependency_count, entry.smoke_status
        ));
    }
    out
}

fn render_docs_markdown(report: &EconomicsReport) -> String {
    format!(
        "# Dependency Economics\n\nRegenerate this table with:\n\n```bash\ncargo xtask economics\n```\n\nThe latest generated receipt also lives at `target/xtask/economics/latest.md`.\n\nThe committed table below intentionally omits machine-dependent timing columns so docs stay stable across CI runners and developer machines.\n\n## Current receipt\n\n{}",
        render_docs_table_markdown(report)
    )
}

fn write_json_report(path: &Path, report: &EconomicsReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize economics JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

fn write_markdown_report(path: &Path, markdown: String) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, markdown).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_package_names_deduplicates_tree_lines() {
        let parsed = parse_package_names(
            "uselesskey-entropy v0.6.0\nuselesskey-core v0.6.0\nuselesskey-core v0.6.0\n",
        );
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("uselesskey-entropy"));
        assert!(parsed.contains("uselesskey-core"));
    }

    #[test]
    fn markdown_contains_headers() {
        let report = EconomicsReport {
            schema_version: 1,
            entries: vec![EconomicsEntry {
                use_case: "entropy-only".to_string(),
                recommended_lane: "uselesskey-entropy".to_string(),
                package: "uselesskey-entropy".to_string(),
                dependency_count: 4,
                first_check_ms: 1000,
                repeat_check_ms: 250,
                check_status: "ok".to_string(),
                smoke_status: "ok".to_string(),
                check_command: "cargo check -p uselesskey-entropy".to_string(),
                smoke_command: None,
                details: None,
            }],
        };

        let markdown = render_table_markdown(&report);
        assert!(markdown.contains("| use case | recommended lane | dep count |"));
        assert!(markdown.contains("| entropy-only | uselesskey-entropy | 4 |"));
    }

    #[test]
    fn docs_markdown_contains_regen_command() {
        let report = EconomicsReport {
            schema_version: 1,
            entries: Vec::new(),
        };

        let markdown = render_docs_markdown(&report);
        assert!(markdown.contains("cargo xtask economics"));
        assert!(markdown.contains("# Dependency Economics"));
    }

    #[test]
    fn docs_markdown_omits_timing_columns() {
        let report = EconomicsReport {
            schema_version: 1,
            entries: vec![EconomicsEntry {
                use_case: "entropy-only".to_string(),
                recommended_lane: "uselesskey-entropy".to_string(),
                package: "uselesskey-entropy".to_string(),
                dependency_count: 4,
                first_check_ms: 1000,
                repeat_check_ms: 250,
                check_status: "ok".to_string(),
                smoke_status: "ok".to_string(),
                check_command: "cargo check -p uselesskey-entropy".to_string(),
                smoke_command: None,
                details: None,
            }],
        };

        let markdown = render_docs_markdown(&report);
        assert!(markdown.contains("| use case | recommended lane | dep count | smoke |"));
        assert!(!markdown.contains("first check"));
        assert!(!markdown.contains("repeat check"));
    }
}

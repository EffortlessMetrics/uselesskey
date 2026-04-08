use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;

const AUDIT_JSON_PATH: &str = "target/xtask/audit-surface/latest.json";
const AUDIT_MARKDOWN_PATH: &str = "target/xtask/audit-surface/latest.md";
const AUDIT_DOCS_PATH: &str = "docs/reference/audit-surface.md";

struct Lane {
    name: &'static str,
    package: &'static str,
}

const LANES: &[Lane] = &[
    Lane {
        name: "entropy",
        package: "uselesskey-entropy",
    },
    Lane {
        name: "token",
        package: "uselesskey-token",
    },
    Lane {
        name: "rsa",
        package: "uselesskey-rsa",
    },
    Lane {
        name: "materialize-shape",
        package: "materialize-shape-buildrs-example",
    },
    Lane {
        name: "materialize-rsa",
        package: "materialize-buildrs-example",
    },
    Lane {
        name: "jsonwebtoken-adapter",
        package: "uselesskey-jsonwebtoken",
    },
    Lane {
        name: "pgp-adapter",
        package: "uselesskey-pgp",
    },
];

#[derive(Debug, Serialize)]
struct AuditSurfaceReport {
    schema_version: u32,
    workspace_deny_status: String,
    entries: Vec<AuditSurfaceEntry>,
}

#[derive(Debug, Serialize)]
struct AuditSurfaceEntry {
    lane: String,
    package: String,
    dependency_count: usize,
    matched_markers: Vec<String>,
    lane_class: String,
}

pub fn audit_surface_cmd() -> Result<()> {
    let workspace_deny_status = workspace_deny_status();
    let mut entries = Vec::with_capacity(LANES.len());

    for lane in LANES {
        eprintln!("==> audit-surface {}", lane.name);
        let tree = cargo_tree(lane.package)?;
        let packages = parse_package_names(&tree);
        let matched_markers = matched_markers(&tree);
        let lane_class = classify_lane(lane.name, &matched_markers);

        entries.push(AuditSurfaceEntry {
            lane: lane.name.to_string(),
            package: lane.package.to_string(),
            dependency_count: packages.len(),
            matched_markers,
            lane_class,
        });
    }

    let report = AuditSurfaceReport {
        schema_version: 1,
        workspace_deny_status,
        entries,
    };
    write_json_report(Path::new(AUDIT_JSON_PATH), &report)?;
    write_markdown_report(
        Path::new(AUDIT_MARKDOWN_PATH),
        render_table_markdown(&report),
    )?;
    write_markdown_report(Path::new(AUDIT_DOCS_PATH), render_docs_markdown(&report))?;

    println!(
        "audit-surface: wrote {} and {}",
        AUDIT_JSON_PATH, AUDIT_MARKDOWN_PATH
    );
    Ok(())
}

fn cargo_tree(package: &str) -> Result<String> {
    let output = Command::new("cargo")
        .args(["tree", "-p", package, "--prefix", "none"])
        .output()
        .with_context(|| format!("failed to run cargo tree for {package}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "cargo tree -p {package} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_package_names(tree: &str) -> BTreeSet<String> {
    tree.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect()
}

fn matched_markers(tree: &str) -> Vec<String> {
    let mut matches = BTreeSet::new();
    for line in tree.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rsa v0.9.") {
            matches.insert("rsa-legacy-0.9".to_string());
        }
        if trimmed.starts_with("rsa v0.10.") {
            matches.insert("rsa-modern-0.10".to_string());
        }
        if trimmed.starts_with("jsonwebtoken v") {
            matches.insert("jsonwebtoken".to_string());
        }
        if trimmed.starts_with("pgp v") {
            matches.insert("pgp".to_string());
        }
        if trimmed.starts_with("ring v") {
            matches.insert("ring".to_string());
        }
        if trimmed.starts_with("rustls v") {
            matches.insert("rustls".to_string());
        }
        if trimmed.starts_with("x509-parser v") || trimmed.starts_with("rcgen v") {
            matches.insert("x509-stack".to_string());
        }
    }
    matches.into_iter().collect()
}

fn classify_lane(lane: &str, markers: &[String]) -> String {
    if lane == "entropy" || lane == "token" || lane == "materialize-shape" {
        if markers.is_empty() {
            return "common-lane-clean".to_string();
        }
        return "common-lane-needs-attention".to_string();
    }

    if markers
        .iter()
        .any(|marker| marker == "pgp" || marker == "jsonwebtoken")
    {
        return "adapter-island".to_string();
    }

    "specialized-lane".to_string()
}

fn workspace_deny_status() -> String {
    match Command::new("cargo").args(["deny", "-V"]).output() {
        Ok(output) if output.status.success() => match Command::new("cargo")
            .args(["deny", "check", "advisories"])
            .output()
        {
            Ok(run) if run.status.success() => "ok".to_string(),
            Ok(_) => "failed".to_string(),
            Err(_) => "unavailable".to_string(),
        },
        _ => "unavailable".to_string(),
    }
}

fn render_table_markdown(report: &AuditSurfaceReport) -> String {
    let mut out = format!(
        "workspace cargo-deny advisories: `{}`\n\n| lane | package | dep count | markers | class |\n| --- | --- | ---: | --- | --- |\n",
        report.workspace_deny_status
    );
    for entry in &report.entries {
        let markers = if entry.matched_markers.is_empty() {
            "none".to_string()
        } else {
            entry.matched_markers.join(", ")
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            entry.lane, entry.package, entry.dependency_count, markers, entry.lane_class
        ));
    }
    out
}

fn render_docs_table_markdown(report: &AuditSurfaceReport) -> String {
    let mut out = format!(
        "workspace cargo-deny advisories: `{}`\n\n| lane | package | markers | class |\n| --- | --- | --- | --- |\n",
        report.workspace_deny_status
    );
    for entry in &report.entries {
        let markers = if entry.matched_markers.is_empty() {
            "none".to_string()
        } else {
            entry.matched_markers.join(", ")
        };
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            entry.lane, entry.package, markers, entry.lane_class
        ));
    }
    out
}

fn render_docs_markdown(report: &AuditSurfaceReport) -> String {
    format!(
        "# Audit Surface\n\nRegenerate this table with:\n\n```bash\ncargo xtask audit-surface\n```\n\nThe latest generated receipt also lives at `target/xtask/audit-surface/latest.md`.\n\nThe committed table below intentionally omits machine-dependent dependency counts so docs stay stable across CI runners and developer machines.\n\n## Current receipt\n\n{}",
        render_docs_table_markdown(report)
    )
}

fn write_json_report(path: &Path, report: &AuditSurfaceReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize audit-surface JSON")?;
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
    fn markers_find_expected_islands() {
        let markers = matched_markers(
            "rsa v0.9.10\njsonwebtoken v10.3.0\nring v0.17.14\nuselesskey-token v0.6.0\n",
        );
        assert!(markers.contains(&"rsa-legacy-0.9".to_string()));
        assert!(markers.contains(&"jsonwebtoken".to_string()));
        assert!(markers.contains(&"ring".to_string()));
    }

    #[test]
    fn classify_entropy_without_markers_as_clean() {
        assert_eq!(classify_lane("entropy", &[]), "common-lane-clean");
    }

    #[test]
    fn classify_materialize_shape_without_markers_as_clean() {
        assert_eq!(classify_lane("materialize-shape", &[]), "common-lane-clean");
    }

    #[test]
    fn classify_jsonwebtoken_as_adapter_island() {
        assert_eq!(
            classify_lane("jsonwebtoken-adapter", &["jsonwebtoken".to_string()]),
            "adapter-island"
        );
    }

    #[test]
    fn docs_markdown_omits_dependency_counts() {
        let report = AuditSurfaceReport {
            schema_version: 1,
            workspace_deny_status: "ok".to_string(),
            entries: vec![AuditSurfaceEntry {
                lane: "entropy".to_string(),
                package: "uselesskey-entropy".to_string(),
                dependency_count: 59,
                matched_markers: Vec::new(),
                lane_class: "common-lane-clean".to_string(),
            }],
        };

        let markdown = render_docs_markdown(&report);
        assert!(markdown.contains("| lane | package | markers | class |"));
        assert!(!markdown.contains("dep count"));
    }
}

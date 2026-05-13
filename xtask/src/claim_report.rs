use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct ClaimReport {
    status: String,
    filter: Option<String>,
    sources: ClaimReportSources,
    claims: Vec<ClaimReportEntry>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClaimReportSources {
    ledger: String,
    public_claims: String,
    specs: String,
    adrs: String,
}

#[derive(Debug, Serialize)]
struct ClaimReportEntry {
    id: String,
    title: String,
    status: String,
    surfaces: Vec<String>,
    spec: Option<LinkedArtifact>,
    docs: Vec<String>,
    proof_commands: Vec<String>,
    artifacts: Vec<String>,
    release_lanes: Vec<String>,
    boundary: String,
    generated_evidence_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct LinkedArtifact {
    id: String,
    title: Option<String>,
    status: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ClaimLedger {
    #[serde(default)]
    claim: Vec<ClaimLedgerEntry>,
}

#[derive(Debug, Deserialize)]
struct ClaimLedgerEntry {
    id: String,
    title: String,
    status: String,
    #[serde(default)]
    spec: Option<String>,
    #[serde(default)]
    surfaces: Vec<String>,
    #[serde(default)]
    proof_commands: Vec<String>,
    #[serde(default)]
    artifacts: Vec<String>,
    #[serde(default)]
    docs: Vec<String>,
    #[serde(default)]
    release_lanes: Vec<String>,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactFrontMatter {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

pub fn run(root: &Path, format: OutputFormat, claim_filter: Option<&str>) -> Result<()> {
    let report = build_report(root, claim_filter)?;
    let out_dir = root.join("target/claim-report");
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let json_path = out_dir.join("public-claims.json");
    let md_path = out_dir.join("public-claims.md");
    write_json_pretty(&json_path, &report)?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("write {}", md_path.display()))?;

    match format {
        OutputFormat::Human => {
            println!("{}", render_markdown(&report));
            println!(
                "claim-report: wrote {} and {}",
                rel_path(root, &md_path),
                rel_path(root, &json_path)
            );
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(())
}

fn build_report(root: &Path, claim_filter: Option<&str>) -> Result<ClaimReport> {
    let ledger_path = root.join("policy/claim-ledger.toml");
    let ledger_text = fs::read_to_string(&ledger_path)
        .with_context(|| format!("read {}", ledger_path.display()))?;
    let ledger: ClaimLedger =
        toml::from_str(&ledger_text).context("parse policy/claim-ledger.toml")?;

    let mut warnings = Vec::new();
    let public_claims_path = root.join("docs/status/PUBLIC_CLAIMS.md");
    if !public_claims_path.exists() {
        warnings.push("docs/status/PUBLIC_CLAIMS.md is missing".to_string());
    }

    let specs = collect_artifacts(root, &root.join("docs/specs"), "USELESSKEY-SPEC-")?;
    let adrs = collect_artifacts(root, &root.join("docs/adr"), "USELESSKEY-ADR-")?;
    let artifacts = specs
        .iter()
        .chain(adrs.iter())
        .map(|(id, artifact)| (id.clone(), artifact.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut claims = Vec::new();
    for claim in ledger.claim {
        if claim_filter.is_some_and(|filter| filter != claim.id) {
            continue;
        }

        let spec = claim.spec.as_ref().map(|id| {
            artifacts.get(id).cloned().unwrap_or_else(|| {
                warnings.push(format!("claim `{}` links missing spec `{id}`", claim.id));
                LinkedArtifact {
                    id: id.clone(),
                    title: None,
                    status: None,
                    path: String::new(),
                }
            })
        });

        for doc in &claim.docs {
            if !root
                .join(doc.replace('/', std::path::MAIN_SEPARATOR_STR))
                .exists()
            {
                warnings.push(format!("claim `{}` links missing doc `{doc}`", claim.id));
            }
        }

        let generated_evidence_paths = claim
            .artifacts
            .iter()
            .filter(|artifact| is_generated_evidence_path(artifact))
            .cloned()
            .collect();

        claims.push(ClaimReportEntry {
            id: claim.id,
            title: claim.title,
            status: claim.status,
            surfaces: claim.surfaces,
            spec,
            docs: claim.docs,
            proof_commands: claim.proof_commands,
            artifacts: claim.artifacts,
            release_lanes: claim.release_lanes,
            boundary: claim.boundary,
            generated_evidence_paths,
        });
    }

    if let Some(filter) = claim_filter
        && claims.is_empty()
    {
        bail!("claim-report: no claim found for `{filter}`");
    }

    let status = "pass".to_string();
    Ok(ClaimReport {
        status,
        filter: claim_filter.map(str::to_string),
        sources: ClaimReportSources {
            ledger: "policy/claim-ledger.toml".to_string(),
            public_claims: "docs/status/PUBLIC_CLAIMS.md".to_string(),
            specs: "docs/specs".to_string(),
            adrs: "docs/adr".to_string(),
        },
        claims,
        warnings,
    })
}

fn collect_artifacts(
    root: &Path,
    dir: &Path,
    prefix: &str,
) -> Result<BTreeMap<String, LinkedArtifact>> {
    let mut artifacts = BTreeMap::new();
    if !dir.exists() {
        return Ok(artifacts);
    }

    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(prefix) {
            continue;
        }

        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let (front_matter, _) = split_toml_front_matter(&text)
            .with_context(|| format!("parse front matter from {}", rel_path(root, &path)))?;
        let parsed: ArtifactFrontMatter = toml::from_str(front_matter)
            .with_context(|| format!("parse TOML front matter from {}", rel_path(root, &path)))?;
        artifacts.insert(
            parsed.id.clone(),
            LinkedArtifact {
                id: parsed.id,
                title: parsed.title,
                status: parsed.status,
                path: rel_path(root, &path),
            },
        );
    }

    Ok(artifacts)
}

fn split_toml_front_matter(text: &str) -> Result<(&str, &str)> {
    let Some(rest) = text.strip_prefix("+++\n") else {
        bail!("missing TOML front matter opening delimiter")
    };
    let Some((front, body)) = rest.split_once("\n+++") else {
        bail!("missing TOML front matter closing delimiter")
    };
    Ok((front.trim(), body.trim_start_matches(['\r', '\n'])))
}

fn render_markdown(report: &ClaimReport) -> String {
    let mut md = String::new();
    md.push_str("# Public Claim Report\n\n");
    md.push_str(
        "This report indexes public `uselesskey` claims from `policy/claim-ledger.toml`.\n",
    );
    md.push_str("It does not run proof commands.\n\n");

    md.push_str("## Sources\n\n");
    md.push_str(&format!("- Ledger: `{}`\n", report.sources.ledger));
    md.push_str(&format!(
        "- Public claim docs: `{}`\n",
        report.sources.public_claims
    ));
    md.push_str(&format!("- Specs: `{}`\n", report.sources.specs));
    md.push_str(&format!("- ADRs: `{}`\n", report.sources.adrs));
    if let Some(filter) = &report.filter {
        md.push_str(&format!("- Filter: `{filter}`\n"));
    }

    md.push_str("\n## Summary\n\n");
    md.push_str("| Claim | Status | Release lanes | Spec |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for claim in &report.claims {
        let spec = claim
            .spec
            .as_ref()
            .map(|spec| format!("`{}`", spec.id))
            .unwrap_or_else(|| "n/a".to_string());
        md.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            claim.id,
            claim.status,
            join_inline(&claim.release_lanes),
            spec
        ));
    }

    md.push_str("\n## Claims\n\n");
    for claim in &report.claims {
        md.push_str(&format!("### {}\n\n", claim.title));
        md.push_str(&format!("- ID: `{}`\n", claim.id));
        md.push_str(&format!("- Status: `{}`\n", claim.status));
        if let Some(spec) = &claim.spec {
            md.push_str(&format!("- Spec: `{}` ({})\n", spec.id, spec.path));
        }
        md.push_str(&format!("- Surfaces: {}\n", join_inline(&claim.surfaces)));
        md.push_str(&format!("- Docs: {}\n", join_inline(&claim.docs)));
        md.push_str(&format!(
            "- Release lanes: {}\n",
            join_inline(&claim.release_lanes)
        ));

        md.push_str("\nProof commands:\n\n");
        md.push_str("```bash\n");
        for command in &claim.proof_commands {
            md.push_str(command);
            md.push('\n');
        }
        md.push_str("```\n\n");

        md.push_str("Artifacts:\n\n");
        for artifact in &claim.artifacts {
            md.push_str(&format!("- `{artifact}`\n"));
        }

        if !claim.generated_evidence_paths.is_empty() {
            md.push_str("\nLast-known generated evidence paths:\n\n");
            for path in &claim.generated_evidence_paths {
                md.push_str(&format!("- `{path}`\n"));
            }
        }

        md.push_str("\nBoundary:\n\n");
        md.push_str(&claim.boundary);
        md.push_str("\n\n");
    }

    if !report.warnings.is_empty() {
        md.push_str("## Warnings\n\n");
        for warning in &report.warnings {
            md.push_str(&format!("- {warning}\n"));
        }
    }

    md
}

fn join_inline(values: &[String]) -> String {
    if values.is_empty() {
        return "n/a".to_string();
    }
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_generated_evidence_path(path: &str) -> bool {
    path.starts_with("badges/") || path.starts_with("target/")
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json + "\n").with_context(|| format!("write {}", path.display()))
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_includes_claim_ledger_fields() {
        let dir = minimal_repo();
        let report = build_report(dir.path(), None).unwrap();

        assert_eq!(report.claims.len(), 2);
        let claim = &report.claims[0];
        assert_eq!(claim.id, "scanner-safe-fixtures");
        assert_eq!(claim.status, "stable");
        assert_eq!(
            claim.spec.as_ref().map(|spec| spec.id.as_str()),
            Some("USELESSKEY-SPEC-0002")
        );
        assert_eq!(
            claim.generated_evidence_paths,
            vec![
                "badges/scanner-safe.json",
                "target/release-evidence/scanner-safe/proof.json"
            ]
        );
        assert!(
            report.warnings.is_empty(),
            "warnings: {:?}",
            report.warnings
        );
    }

    #[test]
    fn claim_filter_selects_one_claim() {
        let dir = minimal_repo();
        let report = build_report(dir.path(), Some("tls-contract-pack")).unwrap();

        assert_eq!(report.claims.len(), 1);
        assert_eq!(report.claims[0].id, "tls-contract-pack");
        assert_eq!(report.filter.as_deref(), Some("tls-contract-pack"));
    }

    #[test]
    fn unknown_claim_filter_fails() {
        let dir = minimal_repo();
        let err = build_report(dir.path(), Some("missing-claim")).unwrap_err();

        assert!(
            err.to_string().contains("no claim found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn markdown_renders_proof_commands_and_boundaries() {
        let dir = minimal_repo();
        let report = build_report(dir.path(), Some("scanner-safe-fixtures")).unwrap();
        let markdown = render_markdown(&report);

        assert!(markdown.contains("# Public Claim Report"));
        assert!(markdown.contains("cargo xtask scanner-safe-reference --check"));
        assert!(markdown.contains("Scanner-safe fixture material"));
    }

    fn minimal_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("policy")).unwrap();
        fs::create_dir_all(dir.path().join("docs/status")).unwrap();
        fs::create_dir_all(dir.path().join("docs/specs")).unwrap();
        fs::create_dir_all(dir.path().join("docs/adr")).unwrap();
        fs::create_dir_all(dir.path().join("docs/how-to")).unwrap();

        fs::write(
            dir.path().join("policy/claim-ledger.toml"),
            r#"[[claim]]
id = "scanner-safe-fixtures"
title = "Scanner-safe fixtures"
status = "stable"
spec = "USELESSKEY-SPEC-0002"
surfaces = ["README badge"]
proof_commands = [
  "cargo xtask scanner-safe-reference --check",
  "cargo xtask badges --check",
]
artifacts = [
  "badges/scanner-safe.json",
  "target/release-evidence/scanner-safe/proof.json",
]
docs = ["docs/how-to/scanner-safe.md"]
release_lanes = ["pr", "patch"]
boundary = "Scanner-safe fixture material does not mean every derived export is safe to commit."

[[claim]]
id = "tls-contract-pack"
title = "TLS contract pack"
status = "stable"
spec = "USELESSKEY-SPEC-0002"
surfaces = ["README"]
proof_commands = ["cargo xtask bundle-proof --profile tls --out target/release-evidence/tls"]
artifacts = ["target/release-evidence/tls/proof.json"]
docs = ["docs/how-to/tls.md"]
release_lanes = ["minor"]
boundary = "TLS fixtures do not prove production PKI."
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("docs/status/PUBLIC_CLAIMS.md"),
            "# Claims\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("docs/how-to/scanner-safe.md"),
            "# Scanner\n",
        )
        .unwrap();
        fs::write(dir.path().join("docs/how-to/tls.md"), "# TLS\n").unwrap();
        fs::write(
            dir.path().join("docs/specs/USELESSKEY-SPEC-0002-claims.md"),
            r#"+++
id = "USELESSKEY-SPEC-0002"
kind = "spec"
title = "Public claim ledger"
status = "accepted"
+++

# Spec
"#,
        )
        .unwrap();
        fs::write(
            dir.path()
                .join("docs/adr/USELESSKEY-ADR-0001-contract-packs.md"),
            r#"+++
id = "USELESSKEY-ADR-0001"
kind = "adr"
title = "Contract packs"
status = "accepted"
+++

# ADR
"#,
        )
        .unwrap();

        dir
    }
}

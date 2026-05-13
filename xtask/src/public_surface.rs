use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const METADATA_PATH: &str = "docs/metadata/workspace-docs.json";

/// Historically held the published-internal `uselesskey-core-*` and
/// `uselesskey-token-spec` shards that wrapped owner-crate `srp::*` modules.
/// All shards were removed in v0.8.0 (PR-4 of the SRP collapse). The list is
/// retained as an empty slice so `package_is_core_shard` continues to reject
/// any future re-introduction of an internal `uselesskey-core-*` shard.
const LEGACY_INTERNAL_SHARDS: &[&str] = &[];

#[derive(Debug, Deserialize)]
struct DocsMetadata {
    workspace_crates: Vec<CrateEntry>,
    adapter_crates: Vec<CrateEntry>,
    support_matrix: Vec<SupportEntry>,
}

#[derive(Debug, Deserialize)]
struct CrateEntry {
    name: String,
    description: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SupportEntry {
    name: String,
    support_tier: String,
    publish_status: String,
    intended_audience: String,
    semver_expectation: String,
    msrv_policy: String,
    deprecation_note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoPackage {
    name: String,
    manifest_path: PathBuf,
    publish: Option<Vec<String>>,
}

pub fn public_surface_cmd(publish_crates: &[&str]) -> Result<()> {
    crate::docs_sync::docs_sync_cmd(true)?;

    let root = crate::workspace_root_path();
    let metadata = load_docs_metadata(&root)?;
    let cargo = cargo_metadata(&root)?;
    let summary = validate_public_surface(&cargo.packages, &metadata, publish_crates)?;

    println!(
        "public-surface: checked {} workspace crates ({} public promises, {} adapter promises, {} published internals, {} workspace-only)",
        summary.workspace_crates,
        summary.public_promises,
        summary.adapter_promises,
        summary.published_internals,
        summary.workspace_only
    );
    Ok(())
}

fn load_docs_metadata(root: &Path) -> Result<DocsMetadata> {
    let path = root.join(METADATA_PATH);
    let raw = fs::read_to_string(&path).context("failed to read workspace docs metadata")?;
    serde_json::from_str(&raw).context("invalid workspace docs metadata JSON")
}

fn cargo_metadata(root: &Path) -> Result<CargoMetadata> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for public-surface guard")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed while checking public surface: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata JSON")
}

fn validate_public_surface(
    packages: &[CargoPackage],
    metadata: &DocsMetadata,
    publish_crates: &[&str],
) -> Result<PublicSurfaceSummary> {
    let support_by_name = metadata
        .support_matrix
        .iter()
        .map(|entry| (entry.name.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let workspace_stories = crate_entries_by_name(&metadata.workspace_crates);
    let adapter_stories = crate_entries_by_name(&metadata.adapter_crates);
    let legacy_internal = LEGACY_INTERNAL_SHARDS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let publish_set = publish_crates.iter().copied().collect::<BTreeSet<_>>();

    let mut errors = Vec::new();
    let mut summary = PublicSurfaceSummary {
        workspace_crates: packages.len(),
        public_promises: 0,
        adapter_promises: 0,
        published_internals: 0,
        workspace_only: 0,
    };

    for package in packages {
        let support = match support_by_name.get(package.name.as_str()) {
            Some(entry) => *entry,
            None => {
                errors.push(format!(
                    "workspace crate '{}' is missing support_matrix metadata",
                    package.name
                ));
                continue;
            }
        };

        if package_is_core_shard(package) && !legacy_internal.contains(package.name.as_str()) {
            errors.push(format!(
                "new internal core shard '{}' is not allowed; add an SRP module under the owning public crate instead",
                package.name
            ));
        }

        let publishable = package.is_publishable();
        match support.publish_status.as_str() {
            "test-only" => {
                summary.workspace_only += 1;
                if publishable {
                    errors.push(format!(
                        "workspace-only crate '{}' must set publish = false",
                        package.name
                    ));
                }
            }
            "published" if support.intended_audience == "repo-internal" => {
                summary.published_internals += 1;
                validate_published_internal(&mut errors, package, support);
            }
            "published" if support.intended_audience == "adapter-users" => {
                summary.adapter_promises += 1;
                validate_adapter_story(&mut errors, package, support, &adapter_stories);
            }
            "published" => {
                summary.public_promises += 1;
                validate_public_story(&mut errors, package, support, &workspace_stories);
            }
            "internal" => {
                summary.published_internals += 1;
                if publishable {
                    errors.push(format!(
                        "internal crate '{}' is still publishable; mark it published-internal or set publish = false",
                        package.name
                    ));
                }
            }
            other => errors.push(format!(
                "crate '{}' has unsupported publish_status '{}'",
                package.name, other
            )),
        }
    }

    let package_names = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    for support in &metadata.support_matrix {
        if !package_names.contains(support.name.as_str()) {
            errors.push(format!(
                "support_matrix entry '{}' does not match a workspace package",
                support.name
            ));
        }
    }

    let metadata_publish_set = metadata
        .support_matrix
        .iter()
        .filter(|entry| entry.publish_status == "published")
        .map(|entry| entry.name.as_str())
        .collect::<BTreeSet<_>>();
    let missing_from_publish_order = metadata_publish_set
        .difference(&publish_set)
        .copied()
        .collect::<Vec<_>>();
    let extra_in_publish_order = publish_set
        .difference(&metadata_publish_set)
        .copied()
        .collect::<Vec<_>>();
    if !missing_from_publish_order.is_empty() {
        errors.push(format!(
            "published crates missing from PUBLISH_CRATES:\n- {}",
            missing_from_publish_order.join("\n- ")
        ));
    }
    if !extra_in_publish_order.is_empty() {
        errors.push(format!(
            "PUBLISH_CRATES contains non-published support entries:\n- {}",
            extra_in_publish_order.join("\n- ")
        ));
    }

    if !errors.is_empty() {
        bail!("public-surface guard failed:\n{}", errors.join("\n"));
    }

    Ok(summary)
}

fn validate_public_story(
    errors: &mut Vec<String>,
    package: &CargoPackage,
    support: &SupportEntry,
    workspace_stories: &BTreeMap<&str, &CrateEntry>,
) {
    validate_common_support_fields(errors, package, support);
    if support.intended_audience == "repo-internal" {
        errors.push(format!(
            "public crate '{}' cannot use repo-internal intended_audience",
            package.name
        ));
    }
    if !package.is_publishable() {
        errors.push(format!(
            "public promise crate '{}' is not publishable",
            package.name
        ));
    }
    match workspace_stories.get(package.name.as_str()) {
        Some(story) if !story.description.trim().is_empty() => {}
        Some(_) => errors.push(format!(
            "public promise crate '{}' has an empty downstream import story",
            package.name
        )),
        None => errors.push(format!(
            "public promise crate '{}' is missing from workspace_crates metadata",
            package.name
        )),
    }
}

fn validate_adapter_story(
    errors: &mut Vec<String>,
    package: &CargoPackage,
    support: &SupportEntry,
    adapter_stories: &BTreeMap<&str, &CrateEntry>,
) {
    validate_common_support_fields(errors, package, support);
    if !package.is_publishable() {
        errors.push(format!(
            "adapter crate '{}' is not publishable",
            package.name
        ));
    }
    match adapter_stories.get(package.name.as_str()) {
        Some(story) if adapter_story_names_downstream_surface(&story.description) => {}
        Some(_) => errors.push(format!(
            "adapter crate '{}' must name a native downstream type, crate, or config in adapter_crates metadata",
            package.name
        )),
        None => errors.push(format!(
            "adapter crate '{}' is missing from adapter_crates metadata",
            package.name
        )),
    }
}

fn validate_published_internal(
    errors: &mut Vec<String>,
    package: &CargoPackage,
    support: &SupportEntry,
) {
    validate_common_support_fields(errors, package, support);
    if !package.is_publishable() {
        errors.push(format!(
            "published internal crate '{}' is not publishable; update publish_status and PUBLISH_CRATES when demoting it",
            package.name
        ));
    }
    if support.support_tier != "experimental" {
        errors.push(format!(
            "published internal crate '{}' must remain experimental until demoted",
            package.name
        ));
    }
    if support
        .deprecation_note
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        errors.push(format!(
            "published internal crate '{}' must carry a deprecation/support note",
            package.name
        ));
    }
}

fn validate_common_support_fields(
    errors: &mut Vec<String>,
    package: &CargoPackage,
    support: &SupportEntry,
) {
    if support.support_tier.trim().is_empty() {
        errors.push(format!("crate '{}' has empty support_tier", package.name));
    }
    if support.semver_expectation.trim().is_empty() {
        errors.push(format!(
            "crate '{}' has empty semver_expectation",
            package.name
        ));
    }
    if support.msrv_policy.trim().is_empty() {
        errors.push(format!("crate '{}' has empty msrv_policy", package.name));
    }
}

fn crate_entries_by_name(entries: &[CrateEntry]) -> BTreeMap<&str, &CrateEntry> {
    entries
        .iter()
        .map(|entry| (entry.name.as_str(), entry))
        .collect()
}

fn package_is_core_shard(package: &CargoPackage) -> bool {
    package.name.starts_with("uselesskey-core-")
        && normalize_path(&package.manifest_path).contains("crates/uselesskey-core-")
}

fn adapter_story_names_downstream_surface(description: &str) -> bool {
    let trimmed = description.trim();
    trimmed.contains('`') || trimmed.to_ascii_lowercase().contains("native")
}

fn normalize_path(path: &Path) -> String {
    path.iter()
        .map(|part| part.to_string_lossy().replace('\\', "/"))
        .collect::<Vec<_>>()
        .join("/")
}

impl CargoPackage {
    fn is_publishable(&self) -> bool {
        !matches!(self.publish.as_ref(), Some(registries) if registries.is_empty())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PublicSurfaceSummary {
    workspace_crates: usize,
    public_promises: usize,
    adapter_promises: usize,
    published_internals: usize,
    workspace_only: usize,
}

#[cfg(test)]
mod tests {
    use super::{CargoPackage, CrateEntry, DocsMetadata, SupportEntry, validate_public_surface};
    use std::path::PathBuf;

    #[test]
    fn unknown_core_shard_is_rejected() {
        let packages = vec![publishable_package(
            "uselesskey-core-new-seam",
            "crates/uselesskey-core-new-seam/Cargo.toml",
        )];
        let metadata = metadata_with(vec![SupportEntry {
            name: "uselesskey-core-new-seam".to_string(),
            support_tier: "experimental".to_string(),
            publish_status: "published".to_string(),
            intended_audience: "repo-internal".to_string(),
            semver_expectation: "No public API stability commitments.".to_string(),
            msrv_policy: "Tracks workspace MSRV.".to_string(),
            deprecation_note: Some("Prefer owner crate modules.".to_string()),
        }]);

        let err = validate_public_surface(&packages, &metadata, &["uselesskey-core-new-seam"])
            .expect_err("must reject shard");

        assert!(
            err.to_string()
                .contains("new internal core shard 'uselesskey-core-new-seam'")
        );
    }

    #[test]
    fn workspace_only_crate_must_not_be_publishable() {
        let packages = vec![publishable_package(
            "uselesskey-feature-grid",
            "crates/uselesskey-feature-grid/Cargo.toml",
        )];
        let metadata = metadata_with(vec![SupportEntry {
            name: "uselesskey-feature-grid".to_string(),
            support_tier: "experimental".to_string(),
            publish_status: "test-only".to_string(),
            intended_audience: "repo-internal".to_string(),
            semver_expectation: "No public API stability commitments.".to_string(),
            msrv_policy: "Best effort.".to_string(),
            deprecation_note: None,
        }]);

        let err =
            validate_public_surface(&packages, &metadata, &[]).expect_err("must reject publish");

        assert!(
            err.to_string().contains(
                "workspace-only crate 'uselesskey-feature-grid' must set publish = false"
            )
        );
    }

    #[test]
    fn public_promise_requires_workspace_story() {
        let packages = vec![publishable_package(
            "uselesskey-new-family",
            "crates/uselesskey-new-family/Cargo.toml",
        )];
        let metadata = metadata_with(vec![SupportEntry {
            name: "uselesskey-new-family".to_string(),
            support_tier: "stable".to_string(),
            publish_status: "published".to_string(),
            intended_audience: "most-users".to_string(),
            semver_expectation: "Normal semver guarantees.".to_string(),
            msrv_policy: "Tracks workspace MSRV.".to_string(),
            deprecation_note: None,
        }]);

        let err = validate_public_surface(&packages, &metadata, &["uselesskey-new-family"])
            .expect_err("must reject story");

        assert!(err.to_string().contains(
            "public promise crate 'uselesskey-new-family' is missing from workspace_crates metadata"
        ));
    }

    #[test]
    fn adapter_promise_requires_downstream_story() {
        let packages = vec![publishable_package(
            "uselesskey-new-adapter",
            "crates/uselesskey-new-adapter/Cargo.toml",
        )];
        let mut metadata = metadata_with(vec![SupportEntry {
            name: "uselesskey-new-adapter".to_string(),
            support_tier: "stable".to_string(),
            publish_status: "published".to_string(),
            intended_audience: "adapter-users".to_string(),
            semver_expectation: "Stable adapter API.".to_string(),
            msrv_policy: "Tracks workspace MSRV.".to_string(),
            deprecation_note: None,
        }]);
        metadata.adapter_crates.push(CrateEntry {
            name: "uselesskey-new-adapter".to_string(),
            description: "Adapter helpers".to_string(),
        });

        let err = validate_public_surface(&packages, &metadata, &["uselesskey-new-adapter"])
            .expect_err("must reject story");

        assert!(
            err.to_string().contains(
                "adapter crate 'uselesskey-new-adapter' must name a native downstream type"
            )
        );
    }

    fn metadata_with(support_matrix: Vec<SupportEntry>) -> DocsMetadata {
        DocsMetadata {
            workspace_crates: vec![CrateEntry {
                name: "uselesskey".to_string(),
                description: "Facade crate".to_string(),
            }],
            adapter_crates: Vec::new(),
            support_matrix,
        }
    }

    fn publishable_package(name: &str, manifest_path: &str) -> CargoPackage {
        CargoPackage {
            name: name.to_string(),
            manifest_path: PathBuf::from(manifest_path),
            publish: None,
        }
    }

    #[test]
    fn publish_crates_must_match_published_support_entries() {
        let packages = vec![publishable_package(
            "uselesskey",
            "crates/uselesskey/Cargo.toml",
        )];
        let mut metadata = metadata_with(vec![SupportEntry {
            name: "uselesskey".to_string(),
            support_tier: "stable".to_string(),
            publish_status: "published".to_string(),
            intended_audience: "most-users".to_string(),
            semver_expectation: "Normal semver guarantees.".to_string(),
            msrv_policy: "Tracks workspace MSRV.".to_string(),
            deprecation_note: None,
        }]);
        metadata.workspace_crates = vec![CrateEntry {
            name: "uselesskey".to_string(),
            description: "Facade crate".to_string(),
        }];

        let err = validate_public_surface(&packages, &metadata, &[])
            .expect_err("must reject missing publish order");

        assert!(
            err.to_string()
                .contains("published crates missing from PUBLISH_CRATES")
        );
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use toml::Value;

const CARGO_MANIFEST: &str = "Cargo.toml";
const CLIPPY_CONFIG: &str = "clippy.toml";
const POLICY_LEDGER: &str = "policy/clippy-lints.toml";
const DEBT_LEDGER: &str = "policy/clippy-debt.toml";
const DOCS_POLICY: &str = "docs/CLIPPY_POLICY.md";

const TEST_CARVEOUTS: &[&str] = &[
    "allow-unwrap-in-tests",
    "allow-expect-in-tests",
    "allow-panic-in-tests",
    "allow-indexing-slicing-in-tests",
    "allow-dbg-in-tests",
];

const PLANNED_BEFORE_MSRV: &[&str] = &[
    "same_length_and_capacity",
    "manual_ilog2",
    "decimal_bitwise_operands",
    "needless_type_cast",
    "disallowed_fields",
    "manual_checked_ops",
    "manual_take",
    "manual_pop_if",
    "duration_suboptimal_units",
    "unnecessary_trailing_comma",
];

#[derive(Debug, Deserialize)]
struct LintLedger {
    schema: u64,
    msrv: String,
    policy: PolicyConfig,
    #[serde(default)]
    planned: Vec<PlannedLint>,
}

#[derive(Debug, Deserialize)]
struct PolicyConfig {
    panic_free_tests: bool,
    allow_test_carveouts: bool,
    suppression_style: String,
    blanket_categories: bool,
    #[serde(default)]
    workspace_inheritance: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PlannedLint {
    name: String,
    level: String,
    activate_when_msrv: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct DebtLedger {
    schema: u64,
    #[serde(default)]
    debt: Vec<DebtEntry>,
}

#[derive(Debug, Deserialize)]
struct DebtEntry {
    lint: String,
    path: String,
    owner: String,
    reason: String,
    expires: String,
}

pub fn check_lint_policy_cmd() -> Result<()> {
    let root_manifest = read_toml(Path::new(CARGO_MANIFEST))?;
    let ledger = read_lint_ledger(Path::new(POLICY_LEDGER))?;

    validate_required_files()?;
    validate_policy_header(&ledger)?;
    validate_workspace_msrv(&root_manifest, &ledger)?;
    validate_workspace_lints(&root_manifest, &ledger)?;
    validate_clippy_config(Path::new(CLIPPY_CONFIG), &ledger)?;
    validate_planned_lints(&root_manifest, &ledger)?;
    validate_debt(Path::new(DEBT_LEDGER))?;

    println!(
        "lint-policy: ok (schema={}, msrv={}, planned={})",
        ledger.schema,
        ledger.msrv,
        ledger.planned.len()
    );
    Ok(())
}

fn validate_required_files() -> Result<()> {
    for path in [
        CARGO_MANIFEST,
        CLIPPY_CONFIG,
        POLICY_LEDGER,
        DEBT_LEDGER,
        DOCS_POLICY,
        "policy/no-panic-allowlist.toml",
        "policy/non-rust-allowlist.toml",
    ] {
        if !Path::new(path).is_file() {
            bail!("required lint policy file is missing: {path}");
        }
    }
    Ok(())
}

fn validate_policy_header(ledger: &LintLedger) -> Result<()> {
    if ledger.schema != 1 {
        bail!("{} must use schema = 1", POLICY_LEDGER);
    }
    if !ledger.policy.panic_free_tests {
        bail!("policy.panic_free_tests must be true");
    }
    if ledger.policy.allow_test_carveouts {
        bail!("policy.allow_test_carveouts must be false");
    }
    if ledger.policy.suppression_style != "expect-with-reason" {
        bail!("policy.suppression_style must be expect-with-reason");
    }
    if ledger.policy.blanket_categories {
        bail!("policy.blanket_categories must be false");
    }

    let inheritance = ledger
        .policy
        .workspace_inheritance
        .as_deref()
        .unwrap_or("required");
    if !matches!(inheritance, "staged" | "required") {
        bail!("policy.workspace_inheritance must be staged or required");
    }
    Ok(())
}

fn validate_workspace_msrv(root_manifest: &Value, ledger: &LintLedger) -> Result<()> {
    let manifest_msrv = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("package"))
        .and_then(|package| package.get("rust-version"))
        .and_then(Value::as_str)
        .context("workspace.package.rust-version is missing")?;

    if manifest_msrv != ledger.msrv {
        bail!(
            "workspace.package.rust-version ({manifest_msrv}) must match {POLICY_LEDGER} msrv ({})",
            ledger.msrv
        );
    }
    Ok(())
}

fn validate_workspace_lints(root_manifest: &Value, ledger: &LintLedger) -> Result<()> {
    let workspace_lints = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("lints"))
        .context("root Cargo.toml must define [workspace.lints]")?;

    for (table, required) in [
        (
            "rust",
            [
                "unsafe_code",
                "unsafe_op_in_unsafe_fn",
                "unused_must_use",
                "unexpected_cfgs",
                "const_item_interior_mutations",
                "function_casts_as_integer",
            ]
            .as_slice(),
        ),
        (
            "clippy",
            [
                "dbg_macro",
                "todo",
                "unimplemented",
                "panic",
                "unreachable",
                "unwrap_used",
                "expect_used",
                "let_underscore_future",
                "let_underscore_must_use",
                "allow_attributes",
                "allow_attributes_without_reason",
            ]
            .as_slice(),
        ),
    ] {
        let lint_table = workspace_lints
            .get(table)
            .and_then(Value::as_table)
            .with_context(|| format!("root Cargo.toml must define [workspace.lints.{table}]"))?;
        for lint in required {
            if !lint_table.contains_key(*lint) {
                bail!("[workspace.lints.{table}] is missing required lint `{lint}`");
            }
        }
    }

    if ledger
        .policy
        .workspace_inheritance
        .as_deref()
        .is_some_and(|mode| mode == "required")
    {
        validate_workspace_member_inheritance(root_manifest)?;
    }
    Ok(())
}

fn validate_workspace_member_inheritance(root_manifest: &Value) -> Result<()> {
    let members = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(Value::as_array)
        .context("workspace.members is missing")?;

    let mut missing = Vec::new();
    for member in members {
        let Some(member) = member.as_str() else {
            continue;
        };
        if member.contains('*') {
            continue;
        }
        let manifest_path = Path::new(member).join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest = read_toml(&manifest_path)?;
        let inherits = manifest
            .get("lints")
            .and_then(|lints| lints.get("workspace"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !inherits {
            missing.push(manifest_path.display().to_string());
        }
    }

    if !missing.is_empty() {
        bail!(
            "workspace lint inheritance is required but missing from:\n{}",
            missing.join("\n")
        );
    }
    Ok(())
}

fn validate_clippy_config(path: &Path, ledger: &LintLedger) -> Result<()> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    for carveout in TEST_CARVEOUTS {
        if raw.contains(carveout) && raw.contains(&format!("{carveout} = true")) {
            bail!("{CLIPPY_CONFIG} must not enable test carveout `{carveout}`");
        }
    }

    let parsed: Value =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    let config_msrv = parsed
        .get("msrv")
        .and_then(Value::as_str)
        .context("clippy.toml must declare msrv")?;
    if config_msrv != ledger.msrv {
        bail!(
            "clippy.toml msrv ({config_msrv}) must match policy msrv ({})",
            ledger.msrv
        );
    }
    Ok(())
}

fn validate_planned_lints(root_manifest: &Value, ledger: &LintLedger) -> Result<()> {
    let mut seen = BTreeSet::new();
    for planned in &ledger.planned {
        for (field_name, value) in [
            ("name", planned.name.as_str()),
            ("level", planned.level.as_str()),
            ("activate_when_msrv", planned.activate_when_msrv.as_str()),
            ("reason", planned.reason.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("planned lint `{}` has empty {field_name}", planned.name);
            }
        }
        if !seen.insert(&planned.name) {
            bail!("duplicate planned lint `{}`", planned.name);
        }
    }

    let clippy_lints = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("lints"))
        .and_then(|lints| lints.get("clippy"))
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();

    for lint in PLANNED_BEFORE_MSRV {
        if clippy_lints.contains_key(*lint) {
            bail!("planned future lint `{lint}` must not be active before the recorded MSRV bump");
        }
    }
    Ok(())
}

fn validate_debt(path: &Path) -> Result<()> {
    let ledger: DebtLedger = read_toml_as(path)?;
    if ledger.schema != 1 {
        bail!("{} must use schema = 1", path.display());
    }

    let today = chrono::Utc::now().date_naive();
    let mut by_identity = BTreeMap::new();
    for debt in ledger.debt {
        for (field_name, value) in [
            ("lint", debt.lint.as_str()),
            ("path", debt.path.as_str()),
            ("owner", debt.owner.as_str()),
            ("reason", debt.reason.as_str()),
            ("expires", debt.expires.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("debt entry for `{}` has empty {field_name}", debt.lint);
            }
        }

        let expires = chrono::NaiveDate::parse_from_str(&debt.expires, "%Y-%m-%d")
            .with_context(|| format!("debt `{}` has invalid expires date", debt.lint))?;
        if expires < today {
            bail!(
                "debt `{}` for `{}` expired on {expires}",
                debt.lint,
                debt.path
            );
        }

        let key = format!("{}\0{}", debt.lint, debt.path);
        if by_identity.insert(key, ()).is_some() {
            bail!(
                "duplicate debt entry for lint `{}` and path `{}`",
                debt.lint,
                debt.path
            );
        }
    }
    Ok(())
}

fn read_lint_ledger(path: &Path) -> Result<LintLedger> {
    read_toml_as(path)
}

fn read_toml(path: &Path) -> Result<Value> {
    read_toml_as(path)
}

fn read_toml_as<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

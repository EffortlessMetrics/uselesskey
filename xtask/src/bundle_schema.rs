use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{read_json_file, target_output, write_json_pretty};

const BUNDLE_MANIFEST_SCHEMA_JSON: &str = "docs/schemas/bundle-manifest.schema.json";
const NEGATIVE_COVERAGE_SCHEMA_JSON: &str = "docs/schemas/negative-coverage.schema.json";
const BUNDLE_AUDIT_SCHEMA_JSON: &str = "docs/schemas/bundle-audit.schema.json";
const AUDIT_RECEIPT_EXAMPLES_DIR: &str = "examples/audit-receipts";
const AUDIT_RECEIPT_REPORT_DIR: &str = "target/source-of-truth";
const AUDIT_RECEIPT_REPORT_JSON: &str = "audit-receipts-check.json";
const AUDIT_RECEIPT_REPORT_MD: &str = "audit-receipts-check.md";
const NEGATIVE_FIXTURES_TOML: &str = "policy/negative-fixtures.toml";
const LOCK_DIR: &str = "target/bundle-schema-check.lock";
const AUDIT_RECEIPT_LOCK_DIR: &str = "target/audit-receipts-check.lock";
const PROFILES: &[&str] = &["scanner-safe", "tls", "oidc", "webhook", "runtime"];

#[derive(Debug, Serialize)]
struct BundleSchemaCheckReport {
    schema_version: u32,
    profiles_checked: usize,
    failure_receipts_checked: usize,
    schemas_checked: Vec<String>,
    profile_reports: Vec<BundleSchemaProfileReport>,
    failure_reports: Vec<BundleSchemaFailureReport>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BundleSchemaProfileReport {
    profile: String,
    bundle_dir: String,
    manifest_path: String,
    negative_coverage_path: String,
    audit_path: String,
    artifact_count: usize,
    receipt_count: usize,
    negative_count: usize,
}

#[derive(Debug, Serialize)]
struct BundleSchemaFailureReport {
    scenario: String,
    audit_path: String,
    failure_class: String,
}

#[derive(Debug, Serialize)]
struct AuditReceiptExamplesReport {
    schema_version: u32,
    examples_checked: usize,
    schema: String,
    examples_dir: String,
    examples: Vec<AuditReceiptExampleReport>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AuditReceiptExampleReport {
    path: String,
    failure_class: String,
    checks: usize,
}

#[derive(Debug, Deserialize)]
struct NegativeFixturePolicy {
    #[serde(default)]
    negative: Vec<NegativeFixturePolicyEntry>,
}

#[derive(Debug, Deserialize)]
struct NegativeFixturePolicyEntry {
    stable_id: String,
    status: String,
    #[serde(default)]
    scanner_safe: Option<bool>,
    #[serde(default)]
    runtime_material: Option<bool>,
    #[serde(default)]
    bundle_exposed: Option<bool>,
    #[serde(default)]
    bundle_profiles: Vec<String>,
}

pub(crate) fn check(out: &Path) -> Result<()> {
    let _output_lock = acquire_output_lock(Path::new("."))?;
    prepare_output_dir(out)?;

    let manifest_schema: Value = read_json_file(Path::new(BUNDLE_MANIFEST_SCHEMA_JSON))?;
    let negative_schema: Value = read_json_file(Path::new(NEGATIVE_COVERAGE_SCHEMA_JSON))?;
    let audit_schema: Value = read_json_file(Path::new(BUNDLE_AUDIT_SCHEMA_JSON))?;
    let negative_policy = load_negative_fixture_policy()?;

    let mut profile_reports = Vec::new();
    let mut errors = Vec::new();
    for profile in PROFILES {
        let bundle_dir = out.join(profile).join("bundle");
        generate_bundle(profile, &bundle_dir)?;
        let manifest_path = bundle_dir.join("manifest.json");
        let negative_coverage_path = bundle_dir.join("receipts/negative-coverage.json");
        let audit_dir = out.join(profile).join("audit");
        generate_bundle_audit(&bundle_dir, &audit_dir)?;
        let audit_path = audit_dir.join("bundle-audit.json");
        let manifest: Value = read_json_file(&manifest_path)?;
        let negative_coverage: Value = read_json_file(&negative_coverage_path)?;
        let audit: Value = read_json_file(&audit_path)?;

        validate_bundle_manifest(&manifest_schema, &manifest, &mut errors);
        validate_negative_coverage(&negative_schema, &negative_coverage, &mut errors);
        validate_negative_coverage_policy_link(
            profile,
            &negative_coverage,
            &negative_policy,
            &mut errors,
        );
        validate_bundle_audit(&audit_schema, &audit, &mut errors);
        validate_manifest_receipt_link(profile, &manifest, &negative_coverage, &mut errors);
        validate_negative_coverage_manifest_link(
            profile,
            &manifest,
            &negative_coverage,
            &mut errors,
        );
        validate_audit_manifest_link(profile, &manifest, &audit, &mut errors);

        profile_reports.push(BundleSchemaProfileReport {
            profile: (*profile).to_string(),
            bundle_dir: normalize_report_path(&bundle_dir),
            manifest_path: normalize_report_path(&manifest_path),
            negative_coverage_path: normalize_report_path(&negative_coverage_path),
            audit_path: normalize_report_path(&audit_path),
            artifact_count: array_len(manifest.get("artifacts")),
            receipt_count: array_len(manifest.get("receipts")),
            negative_count: negative_coverage
                .get("negative_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
        });
    }
    let failure_reports = validate_generated_failure_receipts(&audit_schema, out, &mut errors)?;
    validate_failure_class_coverage(&audit_schema, &failure_reports, &mut errors);

    let report = BundleSchemaCheckReport {
        schema_version: 1,
        profiles_checked: profile_reports.len(),
        failure_receipts_checked: failure_reports.len(),
        schemas_checked: vec![
            BUNDLE_MANIFEST_SCHEMA_JSON.to_string(),
            NEGATIVE_COVERAGE_SCHEMA_JSON.to_string(),
            BUNDLE_AUDIT_SCHEMA_JSON.to_string(),
        ],
        profile_reports,
        failure_reports,
        errors,
    };

    write_json_pretty(&out.join("bundle-schema-check.json"), &report)?;
    fs::write(
        out.join("bundle-schema-check.md"),
        render_bundle_schema_check_markdown(&report),
    )
    .with_context(|| format!("write {}", out.join("bundle-schema-check.md").display()))?;

    eprintln!(
        "bundle-schema-check: {} profiles; {} errors",
        report.profiles_checked,
        report.errors.len()
    );
    if !report.errors.is_empty() {
        for error in report.errors.iter().take(20) {
            eprintln!("  bundle-schema-check error: {error}");
        }
        bail!(
            "bundle-schema-check: {} schema contract error(s)",
            report.errors.len()
        );
    }
    Ok(())
}

pub(crate) fn check_audit_receipts() -> Result<()> {
    let audit_schema: Value = read_json_file(Path::new(BUNDLE_AUDIT_SCHEMA_JSON))?;
    let examples_dir = Path::new(AUDIT_RECEIPT_EXAMPLES_DIR);
    if !examples_dir.is_dir() {
        bail!("audit receipt examples directory missing: {AUDIT_RECEIPT_EXAMPLES_DIR}");
    }

    let mut errors = Vec::new();
    let schema_classes = bundle_audit_failure_classes(&audit_schema, &mut errors);
    let mut example_paths = Vec::new();
    for entry in
        fs::read_dir(examples_dir).with_context(|| format!("read {}", examples_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", examples_dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            example_paths.push(path);
        }
    }
    example_paths.sort();

    let mut examples = Vec::new();
    let mut example_classes = BTreeSet::new();
    for path in example_paths {
        let report_path = normalize_report_path(&path);
        let Some(failure_class) = path.file_stem().and_then(|stem| stem.to_str()) else {
            errors.push(format!("{report_path}: file name is not UTF-8"));
            continue;
        };
        if !is_stable_id(failure_class) {
            errors.push(format!(
                "{report_path}: file stem `{failure_class}` is not a stable failure class ID"
            ));
        }
        if !example_classes.insert(failure_class.to_string()) {
            errors.push(format!(
                "{report_path}: duplicate audit receipt example for `{failure_class}`"
            ));
        }

        let audit: Value = match read_json_file(&path) {
            Ok(audit) => audit,
            Err(err) => {
                errors.push(format!("{report_path}: {err:#}"));
                continue;
            }
        };
        validate_audit_receipt_example(
            &report_path,
            failure_class,
            &audit,
            &audit_schema,
            &schema_classes,
            &mut errors,
        );
        examples.push(AuditReceiptExampleReport {
            path: report_path,
            failure_class: failure_class.to_string(),
            checks: array_len(audit.get("checks")),
        });
    }
    validate_audit_receipt_example_coverage(&schema_classes, &example_classes, &mut errors);

    let report = AuditReceiptExamplesReport {
        schema_version: 1,
        examples_checked: examples.len(),
        schema: BUNDLE_AUDIT_SCHEMA_JSON.to_string(),
        examples_dir: AUDIT_RECEIPT_EXAMPLES_DIR.to_string(),
        examples,
        errors,
    };

    write_audit_receipt_examples_report(&report)?;
    eprintln!(
        "audit-receipts: {} examples; {} errors; wrote {}/{} and {}/{}",
        report.examples_checked,
        report.errors.len(),
        AUDIT_RECEIPT_REPORT_DIR,
        AUDIT_RECEIPT_REPORT_JSON,
        AUDIT_RECEIPT_REPORT_DIR,
        AUDIT_RECEIPT_REPORT_MD
    );
    if !report.errors.is_empty() {
        for error in report.errors.iter().take(20) {
            eprintln!("  audit-receipts error: {error}");
        }
        bail!(
            "audit-receipts: {} committed receipt contract error(s)",
            report.errors.len()
        );
    }
    Ok(())
}

fn write_audit_receipt_examples_report(report: &AuditReceiptExamplesReport) -> Result<()> {
    write_audit_receipt_examples_report_at(Path::new("."), report)
}

fn write_audit_receipt_examples_report_at(
    root: &Path,
    report: &AuditReceiptExamplesReport,
) -> Result<()> {
    let _output_lock = acquire_audit_receipt_output_lock(root)?;
    let out_dir = root.join(AUDIT_RECEIPT_REPORT_DIR);
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    write_json_pretty(&out_dir.join(AUDIT_RECEIPT_REPORT_JSON), report)?;
    let markdown_path = out_dir.join(AUDIT_RECEIPT_REPORT_MD);
    fs::write(
        &markdown_path,
        render_audit_receipt_examples_markdown(report),
    )
    .with_context(|| format!("write {}", markdown_path.display()))?;
    Ok(())
}

fn acquire_output_lock(root: &Path) -> Result<target_output::TargetOutputLock> {
    target_output::acquire_lock(root, LOCK_DIR, "check-bundle-schemas")
}

fn acquire_audit_receipt_output_lock(root: &Path) -> Result<target_output::TargetOutputLock> {
    target_output::acquire_lock(root, AUDIT_RECEIPT_LOCK_DIR, "check-audit-receipts")
}

fn prepare_output_dir(out: &Path) -> Result<()> {
    fs::create_dir_all("target").context("create target directory")?;
    let out = out
        .canonicalize()
        .or_else(|_| {
            let parent = out.parent().unwrap_or_else(|| Path::new("."));
            let canonical_parent = parent.canonicalize()?;
            Ok::<_, std::io::Error>(canonical_parent.join(out.file_name().unwrap_or_default()))
        })
        .with_context(|| format!("resolve {}", out.display()))?;
    let target = Path::new("target")
        .canonicalize()
        .context("resolve target directory")?;
    if !out.starts_with(&target) {
        bail!(
            "bundle schema check output must stay under target/: {}",
            out.display()
        );
    }
    if out.exists() {
        fs::remove_dir_all(&out).with_context(|| format!("remove {}", out.display()))?;
    }
    fs::create_dir_all(&out).with_context(|| format!("create {}", out.display()))
}

fn generate_bundle(profile: &str, bundle_dir: &Path) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "-p",
        "uselesskey-cli",
        "--",
        "bundle",
        "--profile",
        profile,
        "--out",
    ]);
    cmd.arg(bundle_dir);
    run_quiet_command(&mut cmd).with_context(|| format!("generate {profile} bundle"))
}

fn generate_bundle_audit(bundle_dir: &Path, audit_dir: &Path) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "-p",
        "uselesskey-cli",
        "--",
        "audit-bundle",
        "--path",
    ]);
    cmd.arg(bundle_dir);
    cmd.arg("--out");
    cmd.arg(audit_dir);
    run_quiet_command(&mut cmd)
        .with_context(|| format!("audit generated bundle {}", bundle_dir.display()))
}

fn generate_bundle_audit_failure(
    bundle_dir: &Path,
    audit_path: &Path,
    expected_failure_class: &str,
) -> Result<Value> {
    let audit_dir = audit_path
        .parent()
        .context("generated failure audit path has parent directory")?;
    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "-p",
        "uselesskey-cli",
        "--",
        "audit-bundle",
        "--path",
    ]);
    cmd.arg(bundle_dir);
    cmd.arg("--ci");
    cmd.arg("--out");
    cmd.arg(audit_dir);
    eprintln!(" RUN {:?}", cmd);
    let output = cmd.output().context("failed to spawn audit-bundle --ci")?;
    if output.status.success() {
        bail!(
            "audit-bundle --ci unexpectedly passed for {}",
            bundle_dir.display()
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.contains(&format!("audit failed: {expected_failure_class}")) {
        bail!("audit-bundle --ci stderr did not mention `{expected_failure_class}`: {stderr}");
    }
    let stdout_audit: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse CI failure audit JSON for {}", bundle_dir.display()))?;
    let durable_audit = read_json_file(audit_path)
        .with_context(|| format!("read durable CI failure audit {}", audit_path.display()))?;
    if durable_audit != stdout_audit {
        bail!(
            "durable CI failure audit {} did not match stdout JSON",
            audit_path.display()
        );
    }
    let markdown_path = audit_path.with_extension("md");
    let markdown = fs::read_to_string(&markdown_path)
        .with_context(|| format!("read durable CI failure audit {}", markdown_path.display()))?;
    if !markdown.contains(expected_failure_class) {
        bail!(
            "durable CI failure audit markdown {} did not mention `{expected_failure_class}`",
            markdown_path.display()
        );
    }
    Ok(durable_audit)
}

fn validate_generated_failure_receipts(
    audit_schema: &Value,
    out: &Path,
    errors: &mut Vec<String>,
) -> Result<Vec<BundleSchemaFailureReport>> {
    let mut reports = Vec::new();

    let missing_manifest_bundle = out.join("ci-failure-missing-manifest").join("bundle");
    fs::create_dir_all(&missing_manifest_bundle)
        .with_context(|| format!("create {}", missing_manifest_bundle.display()))?;
    let missing_manifest_audit = out
        .join("ci-failure-missing-manifest")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &missing_manifest_bundle,
        &missing_manifest_audit,
        "missing_manifest",
    )?;
    validate_failure_receipt(
        "ci-failure-missing-manifest",
        &audit,
        "missing_manifest",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-missing-manifest".to_string(),
        audit_path: normalize_report_path(&missing_manifest_audit),
        failure_class: "missing_manifest".to_string(),
    });

    let invalid_manifest_bundle = out.join("ci-failure-invalid-manifest").join("bundle");
    fs::create_dir_all(&invalid_manifest_bundle)
        .with_context(|| format!("create {}", invalid_manifest_bundle.display()))?;
    fs::write(invalid_manifest_bundle.join("manifest.json"), "{ not json")
        .with_context(|| format!("write {}", invalid_manifest_bundle.display()))?;
    let invalid_manifest_audit = out
        .join("ci-failure-invalid-manifest")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &invalid_manifest_bundle,
        &invalid_manifest_audit,
        "invalid_manifest",
    )?;
    validate_failure_receipt(
        "ci-failure-invalid-manifest",
        &audit,
        "invalid_manifest",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-invalid-manifest".to_string(),
        audit_path: normalize_report_path(&invalid_manifest_audit),
        failure_class: "invalid_manifest".to_string(),
    });

    let path_escape_bundle = out.join("ci-failure-path-escape").join("bundle");
    generate_bundle("scanner-safe", &path_escape_bundle)?;
    let manifest_path = path_escape_bundle.join("manifest.json");
    let mut manifest: Value = read_json_file(&manifest_path)?;
    let files = manifest
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .context("generated manifest has files array")?;
    let first_file = files
        .first_mut()
        .context("generated manifest has at least one file")?;
    *first_file = Value::String("../escape.json".to_string());
    write_json_pretty(&manifest_path, &manifest)?;
    let path_escape_audit = out.join("ci-failure-path-escape").join("bundle-audit.json");
    let audit =
        generate_bundle_audit_failure(&path_escape_bundle, &path_escape_audit, "path_escape")?;
    validate_failure_receipt(
        "ci-failure-path-escape",
        &audit,
        "path_escape",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-path-escape".to_string(),
        audit_path: normalize_report_path(&path_escape_audit),
        failure_class: "path_escape".to_string(),
    });

    let missing_artifact_bundle = out.join("ci-failure-missing-artifact").join("bundle");
    generate_bundle("scanner-safe", &missing_artifact_bundle)?;
    let manifest_path = missing_artifact_bundle.join("manifest.json");
    let manifest: Value = read_json_file(&manifest_path)?;
    let missing_artifact_path = manifest
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(Value::as_str)
        .context("generated manifest has at least one file")?;
    let missing_artifact_file = missing_artifact_bundle.join(missing_artifact_path);
    fs::remove_file(&missing_artifact_file)
        .with_context(|| format!("remove {}", missing_artifact_file.display()))?;
    let missing_artifact_audit = out
        .join("ci-failure-missing-artifact")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &missing_artifact_bundle,
        &missing_artifact_audit,
        "missing_artifact",
    )?;
    validate_failure_receipt(
        "ci-failure-missing-artifact",
        &audit,
        "missing_artifact",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-missing-artifact".to_string(),
        audit_path: normalize_report_path(&missing_artifact_audit),
        failure_class: "missing_artifact".to_string(),
    });

    let unexpected_artifact_bundle = out.join("ci-failure-unexpected-artifact").join("bundle");
    generate_bundle("scanner-safe", &unexpected_artifact_bundle)?;
    let unexpected_artifact_file = unexpected_artifact_bundle.join("unexpected-artifact.json");
    fs::write(&unexpected_artifact_file, "{}")
        .with_context(|| format!("write {}", unexpected_artifact_file.display()))?;
    let unexpected_artifact_audit = out
        .join("ci-failure-unexpected-artifact")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &unexpected_artifact_bundle,
        &unexpected_artifact_audit,
        "unexpected_artifact",
    )?;
    validate_failure_receipt(
        "ci-failure-unexpected-artifact",
        &audit,
        "unexpected_artifact",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-unexpected-artifact".to_string(),
        audit_path: normalize_report_path(&unexpected_artifact_audit),
        failure_class: "unexpected_artifact".to_string(),
    });

    let missing_receipt_bundle = out.join("ci-failure-missing-receipt").join("bundle");
    generate_bundle("scanner-safe", &missing_receipt_bundle)?;
    let manifest_path = missing_receipt_bundle.join("manifest.json");
    let mut manifest: Value = read_json_file(&manifest_path)?;
    let missing_receipt_path = {
        let receipts = manifest
            .get_mut("receipts")
            .and_then(Value::as_array_mut)
            .context("generated manifest has receipts array")?;
        let receipt_index = receipts
            .iter()
            .position(|receipt| {
                receipt.get("kind").and_then(Value::as_str) == Some("audit-surface")
            })
            .context("generated manifest has audit-surface receipt")?;
        let receipt_path = receipts[receipt_index]
            .get("path")
            .and_then(Value::as_str)
            .context("generated audit-surface receipt has path")?
            .to_string();
        receipts.remove(receipt_index);
        receipt_path
    };
    let files = manifest
        .get_mut("files")
        .and_then(Value::as_array_mut)
        .context("generated manifest has files array")?;
    files.retain(|file| file.as_str() != Some(missing_receipt_path.as_str()));
    write_json_pretty(&manifest_path, &manifest)?;
    let missing_receipt_file = missing_receipt_bundle.join(&missing_receipt_path);
    fs::remove_file(&missing_receipt_file)
        .with_context(|| format!("remove {}", missing_receipt_file.display()))?;
    let missing_receipt_audit = out
        .join("ci-failure-missing-receipt")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &missing_receipt_bundle,
        &missing_receipt_audit,
        "missing_receipt",
    )?;
    validate_failure_receipt(
        "ci-failure-missing-receipt",
        &audit,
        "missing_receipt",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-missing-receipt".to_string(),
        audit_path: normalize_report_path(&missing_receipt_audit),
        failure_class: "missing_receipt".to_string(),
    });

    let invalid_receipt_bundle = out.join("ci-failure-invalid-receipt").join("bundle");
    generate_bundle("scanner-safe", &invalid_receipt_bundle)?;
    let invalid_receipt_file = invalid_receipt_bundle.join("receipts/audit-surface.json");
    fs::write(&invalid_receipt_file, "{ not json")
        .with_context(|| format!("write {}", invalid_receipt_file.display()))?;
    let invalid_receipt_audit = out
        .join("ci-failure-invalid-receipt")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &invalid_receipt_bundle,
        &invalid_receipt_audit,
        "invalid_receipt",
    )?;
    validate_failure_receipt(
        "ci-failure-invalid-receipt",
        &audit,
        "invalid_receipt",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-invalid-receipt".to_string(),
        audit_path: normalize_report_path(&invalid_receipt_audit),
        failure_class: "invalid_receipt".to_string(),
    });

    let scanner_safe_mismatch_bundle = out.join("ci-failure-scanner-safe-mismatch").join("bundle");
    generate_bundle("scanner-safe", &scanner_safe_mismatch_bundle)?;
    let scanner_safe_receipt_file =
        scanner_safe_mismatch_bundle.join("receipts/audit-surface.json");
    let mut receipt: Value = read_json_file(&scanner_safe_receipt_file)?;
    receipt["scanner_safe_count"] = Value::from(0);
    write_json_pretty(&scanner_safe_receipt_file, &receipt)?;
    let scanner_safe_mismatch_audit = out
        .join("ci-failure-scanner-safe-mismatch")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &scanner_safe_mismatch_bundle,
        &scanner_safe_mismatch_audit,
        "scanner_safe_mismatch",
    )?;
    validate_failure_receipt(
        "ci-failure-scanner-safe-mismatch",
        &audit,
        "scanner_safe_mismatch",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-scanner-safe-mismatch".to_string(),
        audit_path: normalize_report_path(&scanner_safe_mismatch_audit),
        failure_class: "scanner_safe_mismatch".to_string(),
    });

    let runtime_material_mismatch_bundle = out
        .join("ci-failure-runtime-material-mismatch")
        .join("bundle");
    generate_bundle("scanner-safe", &runtime_material_mismatch_bundle)?;
    let runtime_material_receipt_file =
        runtime_material_mismatch_bundle.join("receipts/audit-surface.json");
    let mut receipt: Value = read_json_file(&runtime_material_receipt_file)?;
    receipt["runtime_material_count"] = Value::from(1);
    write_json_pretty(&runtime_material_receipt_file, &receipt)?;
    let runtime_material_mismatch_audit = out
        .join("ci-failure-runtime-material-mismatch")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &runtime_material_mismatch_bundle,
        &runtime_material_mismatch_audit,
        "runtime_material_mismatch",
    )?;
    validate_failure_receipt(
        "ci-failure-runtime-material-mismatch",
        &audit,
        "runtime_material_mismatch",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-runtime-material-mismatch".to_string(),
        audit_path: normalize_report_path(&runtime_material_mismatch_audit),
        failure_class: "runtime_material_mismatch".to_string(),
    });

    let profile_validation_bundle = out.join("ci-failure-profile-validation").join("bundle");
    generate_bundle("scanner-safe", &profile_validation_bundle)?;
    let manifest_path = profile_validation_bundle.join("manifest.json");
    let manifest: Value = read_json_file(&manifest_path)?;
    let profile_validation_path = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| artifacts.first())
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
        .context("generated manifest has at least one artifact path")?;
    let profile_validation_file = profile_validation_bundle.join(profile_validation_path);
    fs::write(&profile_validation_file, b"profile validation mismatch")
        .with_context(|| format!("write {}", profile_validation_file.display()))?;
    let profile_validation_audit = out
        .join("ci-failure-profile-validation")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &profile_validation_bundle,
        &profile_validation_audit,
        "profile_validation_failed",
    )?;
    validate_failure_receipt(
        "ci-failure-profile-validation",
        &audit,
        "profile_validation_failed",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-profile-validation".to_string(),
        audit_path: normalize_report_path(&profile_validation_audit),
        failure_class: "profile_validation_failed".to_string(),
    });

    let unsupported_profile_bundle = out.join("ci-failure-unsupported-profile").join("bundle");
    generate_bundle("scanner-safe", &unsupported_profile_bundle)?;
    let manifest_path = unsupported_profile_bundle.join("manifest.json");
    let mut manifest: Value = read_json_file(&manifest_path)?;
    manifest["profile"] = Value::String("future-profile".to_string());
    write_json_pretty(&manifest_path, &manifest)?;
    let unsupported_profile_audit = out
        .join("ci-failure-unsupported-profile")
        .join("bundle-audit.json");
    let audit = generate_bundle_audit_failure(
        &unsupported_profile_bundle,
        &unsupported_profile_audit,
        "unsupported_profile",
    )?;
    validate_failure_receipt(
        "ci-failure-unsupported-profile",
        &audit,
        "unsupported_profile",
        audit_schema,
        errors,
    );
    reports.push(BundleSchemaFailureReport {
        scenario: "ci-failure-unsupported-profile".to_string(),
        audit_path: normalize_report_path(&unsupported_profile_audit),
        failure_class: "unsupported_profile".to_string(),
    });

    Ok(reports)
}

fn validate_failure_class_coverage(
    audit_schema: &Value,
    failure_reports: &[BundleSchemaFailureReport],
    errors: &mut Vec<String>,
) {
    let schema_classes = bundle_audit_failure_classes(audit_schema, errors);

    let mut generated_classes = BTreeSet::new();
    for report in failure_reports {
        let class = report.failure_class.as_str();
        if !generated_classes.insert(class.to_string()) {
            errors.push(format!(
                "generated CI failure receipts duplicate failure_class `{class}`"
            ));
        }
    }

    for missing in schema_classes.difference(&generated_classes) {
        errors.push(format!(
            "bundle-audit failure_class `{missing}` has no generated CI failure receipt"
        ));
    }
    for extra in generated_classes.difference(&schema_classes) {
        errors.push(format!(
            "generated CI failure receipt class `{extra}` is not listed in bundle-audit schema"
        ));
    }
}

fn bundle_audit_failure_classes(
    audit_schema: &Value,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let Some(classes) = audit_schema
        .pointer("/$defs/failure_class/enum")
        .and_then(Value::as_array)
    else {
        errors.push("bundle-audit schema is missing $defs.failure_class.enum".to_string());
        return BTreeSet::new();
    };

    let mut schema_classes = BTreeSet::new();
    for (idx, class) in classes.iter().enumerate() {
        let Some(class) = class.as_str() else {
            errors.push(format!(
                "bundle-audit schema failure_class enum[{idx}] is not a string"
            ));
            continue;
        };
        if !schema_classes.insert(class.to_string()) {
            errors.push(format!(
                "bundle-audit schema failure_class enum duplicates `{class}`"
            ));
        }
    }
    schema_classes
}

fn validate_failure_receipt(
    scenario: &str,
    audit: &Value,
    expected_failure_class: &str,
    audit_schema: &Value,
    errors: &mut Vec<String>,
) {
    let mut local_errors = Vec::new();
    validate_bundle_audit(audit_schema, audit, &mut local_errors);
    for error in local_errors {
        errors.push(format!("{scenario}: {error}"));
    }
    if audit.get("status").and_then(Value::as_str) != Some("fail") {
        errors.push(format!(
            "{scenario}: expected status `fail`, found {:?}",
            audit.get("status")
        ));
    }
    if audit.get("profile").and_then(Value::as_str) != Some("unknown") {
        errors.push(format!(
            "{scenario}: expected profile `unknown`, found {:?}",
            audit.get("profile")
        ));
    }
    if audit.get("manifest_version").and_then(Value::as_u64) != Some(0) {
        errors.push(format!(
            "{scenario}: expected manifest_version 0, found {:?}",
            audit.get("manifest_version")
        ));
    }
    for (field, expected) in [
        ("artifact_count", 0_u64),
        ("receipt_count", 0),
        ("scanner_safe_count", 0),
        ("runtime_material_count", 0),
    ] {
        if audit.get(field).and_then(Value::as_u64) != Some(expected) {
            errors.push(format!(
                "{scenario}: expected {field} {expected}, found {:?}",
                audit.get(field)
            ));
        }
    }
    for field in [
        "files",
        "artifacts",
        "receipts",
        "missing_files",
        "unexpected_files",
    ] {
        if array_len(audit.get(field)) != 0 {
            errors.push(format!(
                "{scenario}: expected empty {field}, found {:?}",
                audit.get(field)
            ));
        }
    }
    let failure_class = audit
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| checks.first())
        .and_then(|check| check.get("failure_class"))
        .and_then(Value::as_str);
    if failure_class != Some(expected_failure_class) {
        errors.push(format!(
            "{scenario}: expected failure_class `{expected_failure_class}`, found {failure_class:?}"
        ));
    }
}

fn validate_audit_receipt_example(
    report_path: &str,
    expected_failure_class: &str,
    audit: &Value,
    audit_schema: &Value,
    schema_classes: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let mut local_errors = Vec::new();
    validate_bundle_audit(audit_schema, audit, &mut local_errors);
    validate_audit_receipt_allowed_fields(audit, "bundle-audit.json", &mut local_errors);
    validate_no_audit_receipt_material("bundle-audit.json", audit, &mut local_errors);
    for error in local_errors {
        errors.push(format!("{report_path}: {error}"));
    }

    if !schema_classes.contains(expected_failure_class) {
        errors.push(format!(
            "{report_path}: `{expected_failure_class}` is not listed in {BUNDLE_AUDIT_SCHEMA_JSON}"
        ));
    }
    if audit.get("status").and_then(Value::as_str) != Some("fail") {
        errors.push(format!(
            "{report_path}: expected status `fail`, found {:?}",
            audit.get("status")
        ));
    }
    if let Some(bundle_path) = audit.get("bundle_path").and_then(Value::as_str)
        && !is_safe_relative_path(bundle_path)
    {
        errors.push(format!(
            "{report_path}: bundle_path is not upload-safe relative metadata `{}`",
            display_schema_path(bundle_path)
        ));
    }

    let checks = audit
        .get("checks")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if checks.len() != 1 {
        errors.push(format!(
            "{report_path}: expected exactly one failure check, found {}",
            checks.len()
        ));
    }
    let failure_class = checks
        .first()
        .and_then(|check| check.get("failure_class"))
        .and_then(Value::as_str);
    if failure_class != Some(expected_failure_class) {
        errors.push(format!(
            "{report_path}: expected checks[0].failure_class `{expected_failure_class}`, found {failure_class:?}"
        ));
    }
    let check_status = checks
        .first()
        .and_then(|check| check.get("status"))
        .and_then(Value::as_str);
    if check_status != Some("fail") {
        errors.push(format!(
            "{report_path}: expected checks[0].status `fail`, found {check_status:?}"
        ));
    }
}

fn validate_audit_receipt_example_coverage(
    schema_classes: &BTreeSet<String>,
    example_classes: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    for missing in schema_classes.difference(example_classes) {
        errors.push(format!(
            "bundle-audit failure_class `{missing}` has no committed audit receipt example"
        ));
    }
    for extra in example_classes.difference(schema_classes) {
        errors.push(format!(
            "committed audit receipt example class `{extra}` is not listed in bundle-audit schema"
        ));
    }
}

fn validate_audit_receipt_allowed_fields(audit: &Value, path: &str, errors: &mut Vec<String>) {
    validate_allowed_object_keys(
        audit,
        path,
        &[
            "version",
            "status",
            "bundle_path",
            "profile",
            "manifest_version",
            "manifest_path",
            "artifact_count",
            "receipt_count",
            "scanner_safe_count",
            "runtime_material_count",
            "files",
            "artifacts",
            "receipts",
            "missing_files",
            "unexpected_files",
            "checks",
            "boundaries",
            "does_not_prove",
        ],
        errors,
    );

    if let Some(artifacts) = audit.get("artifacts").and_then(Value::as_array) {
        for (idx, artifact) in artifacts.iter().enumerate() {
            validate_allowed_object_keys(
                artifact,
                &format!("{path}.artifacts[{idx}]"),
                &[
                    "path",
                    "kind",
                    "format",
                    "scanner_safe",
                    "runtime_material",
                    "description",
                ],
                errors,
            );
        }
    }
    if let Some(receipts) = audit.get("receipts").and_then(Value::as_array) {
        for (idx, receipt) in receipts.iter().enumerate() {
            validate_allowed_object_keys(
                receipt,
                &format!("{path}.receipts[{idx}]"),
                &["path", "kind", "profile", "description"],
                errors,
            );
        }
    }
    if let Some(checks) = audit.get("checks").and_then(Value::as_array) {
        for (idx, check) in checks.iter().enumerate() {
            validate_allowed_object_keys(
                check,
                &format!("{path}.checks[{idx}]"),
                &["name", "status", "failure_class", "detail"],
                errors,
            );
        }
    }
}

fn validate_allowed_object_keys(
    value: &Value,
    path: &str,
    allowed: &[&str],
    errors: &mut Vec<String>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{path}: unsupported field `{key}`"));
        }
    }
}

fn validate_no_audit_receipt_material(path: &str, value: &Value, errors: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let child_path = format!("{path}.{key}");
                if is_forbidden_audit_receipt_key(key) {
                    errors.push(format!(
                        "{child_path}: forbidden raw-material field name in audit receipt example"
                    ));
                }
                validate_no_audit_receipt_material(&child_path, value, errors);
            }
        }
        Value::Array(values) => {
            for (idx, value) in values.iter().enumerate() {
                validate_no_audit_receipt_material(&format!("{path}[{idx}]"), value, errors);
            }
        }
        Value::String(value) => {
            for marker in [
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            ] {
                if value.contains(marker) {
                    errors.push(format!(
                        "{path}: forbidden payload marker `{marker}` in audit receipt example"
                    ));
                }
            }
            for snippet in [
                "\"d\":", "\"p\":", "\"q\":", "\"dp\":", "\"dq\":", "\"qi\":", "\"k\":",
            ] {
                if value.contains(snippet) {
                    errors.push(format!(
                        "{path}: forbidden private JWK member snippet `{snippet}` in audit receipt example"
                    ));
                }
            }
            if looks_like_jwt_value(value) {
                errors.push(format!(
                    "{path}: forbidden JWT-shaped value in audit receipt example"
                ));
            }
        }
        _ => {}
    }
}

fn is_forbidden_audit_receipt_key(key: &str) -> bool {
    matches!(
        key,
        "d" | "p"
            | "q"
            | "dp"
            | "dq"
            | "qi"
            | "oth"
            | "k"
            | "key"
            | "secret"
            | "hmac_secret"
            | "request_body"
            | "body"
            | "raw_body"
            | "payload"
            | "raw_payload"
            | "webhook_body"
    )
}

fn looks_like_jwt_value(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && value.len() >= 30
        && parts.iter().all(|part| {
            part.len() >= 8
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '='))
        })
}

fn run_quiet_command(cmd: &mut Command) -> Result<()> {
    eprintln!(" RUN {:?}", cmd);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to spawn command")?;
    if !status.success() {
        bail!("command failed with status: {status}");
    }
    Ok(())
}

fn load_negative_fixture_policy() -> Result<BTreeMap<String, NegativeFixturePolicyEntry>> {
    let raw = fs::read_to_string(NEGATIVE_FIXTURES_TOML)
        .with_context(|| format!("read {NEGATIVE_FIXTURES_TOML}"))?;
    let policy: NegativeFixturePolicy =
        toml::from_str(&raw).with_context(|| format!("parse {NEGATIVE_FIXTURES_TOML}"))?;
    Ok(policy
        .negative
        .into_iter()
        .map(|entry| (entry.stable_id.clone(), entry))
        .collect())
}

fn validate_bundle_manifest(schema: &Value, manifest: &Value, errors: &mut Vec<String>) {
    validate_required_fields(schema, "", manifest, "manifest.json", errors);
    validate_object_type(manifest, "manifest.json", errors);
    validate_positive_integer(manifest.get("version"), "manifest.json.version", errors);
    validate_enum(
        manifest.get("profile"),
        schema.pointer("/$defs/profile/enum"),
        "manifest.json.profile",
        errors,
    );
    validate_string(manifest.get("label"), "manifest.json.label", errors);
    validate_string(manifest.get("seed"), "manifest.json.seed", errors);
    validate_string(manifest.get("format"), "manifest.json.format", errors);

    let file_values = validate_array(manifest.get("files"), "manifest.json.files", errors);
    let mut seen_files = std::collections::BTreeSet::new();
    for (idx, value) in file_values.iter().enumerate() {
        let path = format!("manifest.json.files[{idx}]");
        validate_relative_path(value, &path, errors);
        if let Some(file) = value.as_str()
            && !seen_files.insert(file)
        {
            errors.push(format!("{path}: duplicate path `{file}`"));
        }
    }

    let artifacts = validate_array(manifest.get("artifacts"), "manifest.json.artifacts", errors);
    for (idx, artifact) in artifacts.iter().enumerate() {
        let path = format!("manifest.json.artifacts[{idx}]");
        validate_required_fields(schema, "/$defs/artifact", artifact, &path, errors);
        validate_object_type(artifact, &path, errors);
        validate_relative_path(
            artifact.get("path").unwrap_or(&Value::Null),
            &format!("{path}.path"),
            errors,
        );
        validate_string(artifact.get("kind"), &format!("{path}.kind"), errors);
        validate_string(artifact.get("format"), &format!("{path}.format"), errors);
        validate_enum(
            artifact.get("profile"),
            schema.pointer("/$defs/profile/enum"),
            &format!("{path}.profile"),
            errors,
        );
        validate_string_array(
            artifact.get("lanes"),
            &["scanner-safe", "runtime", "materialized"],
            &format!("{path}.lanes"),
            true,
            errors,
        );
        validate_bool(
            artifact.get("scanner_safe"),
            &format!("{path}.scanner_safe"),
            errors,
        );
        validate_string(
            artifact.get("description"),
            &format!("{path}.description"),
            errors,
        );
    }

    let receipts = validate_array(manifest.get("receipts"), "manifest.json.receipts", errors);
    for (idx, receipt) in receipts.iter().enumerate() {
        let path = format!("manifest.json.receipts[{idx}]");
        validate_required_fields(schema, "/$defs/receipt", receipt, &path, errors);
        validate_object_type(receipt, &path, errors);
        validate_relative_path(
            receipt.get("path").unwrap_or(&Value::Null),
            &format!("{path}.path"),
            errors,
        );
        validate_string(receipt.get("kind"), &format!("{path}.kind"), errors);
        validate_enum(
            receipt.get("profile"),
            schema.pointer("/$defs/profile/enum"),
            &format!("{path}.profile"),
            errors,
        );
        validate_string(
            receipt.get("description"),
            &format!("{path}.description"),
            errors,
        );
    }

    validate_manifest_file_links(&file_values, &artifacts, &receipts, errors);
}

fn validate_negative_coverage(schema: &Value, receipt: &Value, errors: &mut Vec<String>) {
    validate_required_fields(schema, "", receipt, "negative-coverage.json", errors);
    validate_object_type(receipt, "negative-coverage.json", errors);
    if receipt.get("receipt").and_then(Value::as_str) != Some("negative-coverage") {
        errors.push("negative-coverage.json.receipt: expected `negative-coverage`".to_string());
    }
    validate_positive_integer(
        receipt.get("version"),
        "negative-coverage.json.version",
        errors,
    );
    validate_enum(
        receipt.get("profile"),
        schema.pointer("/properties/profile/enum"),
        "negative-coverage.json.profile",
        errors,
    );
    validate_nonnegative_integer(
        receipt.get("negative_count"),
        "negative-coverage.json.negative_count",
        errors,
    );
    let coverage = validate_array(
        receipt.get("coverage"),
        "negative-coverage.json.coverage",
        errors,
    );
    if receipt.get("negative_count").and_then(Value::as_u64) != Some(coverage.len() as u64) {
        errors.push(format!(
            "negative-coverage.json.negative_count: expected {}, found {:?}",
            coverage.len(),
            receipt.get("negative_count")
        ));
    }
    for (idx, entry) in coverage.iter().enumerate() {
        let path = format!("negative-coverage.json.coverage[{idx}]");
        validate_required_fields(schema, "/$defs/coverage_entry", entry, &path, errors);
        validate_object_type(entry, &path, errors);
        validate_relative_path(
            entry.get("path").unwrap_or(&Value::Null),
            &format!("{path}.path"),
            errors,
        );
        validate_string(entry.get("kind"), &format!("{path}.kind"), errors);
        validate_stable_id(
            entry.get("failure_class"),
            &format!("{path}.failure_class"),
            errors,
        );
        validate_string(
            entry.get("expected_failure"),
            &format!("{path}.expected_failure"),
            errors,
        );
        validate_bool(
            entry.get("scanner_safe"),
            &format!("{path}.scanner_safe"),
            errors,
        );
        validate_bool(
            entry.get("runtime_material"),
            &format!("{path}.runtime_material"),
            errors,
        );
        validate_string(
            entry.get("description"),
            &format!("{path}.description"),
            errors,
        );
    }
    validate_string_array(
        receipt.get("boundaries"),
        &[],
        "negative-coverage.json.boundaries",
        true,
        errors,
    );
}

fn validate_negative_coverage_policy_link(
    expected_profile: &str,
    receipt: &Value,
    policy: &BTreeMap<String, NegativeFixturePolicyEntry>,
    errors: &mut Vec<String>,
) {
    let coverage = receipt
        .get("coverage")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (idx, entry) in coverage.iter().enumerate() {
        let path = format!("negative-coverage.json.coverage[{idx}]");
        let Some(failure_class) = entry.get("failure_class").and_then(Value::as_str) else {
            continue;
        };
        let Some(policy_entry) = policy.get(failure_class) else {
            errors.push(format!(
                "{path}.failure_class: `{failure_class}` is not present in {NEGATIVE_FIXTURES_TOML}"
            ));
            continue;
        };

        if policy_entry.status != "implemented" {
            errors.push(format!(
                "{path}.failure_class: `{failure_class}` has policy status `{}`; generated bundle receipts require implemented entries",
                policy_entry.status
            ));
        }
        if policy_entry.bundle_exposed != Some(true) {
            errors.push(format!(
                "{path}.failure_class: `{failure_class}` is not bundle_exposed=true in {NEGATIVE_FIXTURES_TOML}"
            ));
        }
        if !policy_entry
            .bundle_profiles
            .iter()
            .any(|profile| profile == expected_profile)
        {
            errors.push(format!(
                "{path}.failure_class: `{failure_class}` is not exposed for profile `{expected_profile}` in {NEGATIVE_FIXTURES_TOML}"
            ));
        }

        compare_optional_bool(
            entry.get("scanner_safe").and_then(Value::as_bool),
            policy_entry.scanner_safe,
            &format!("{path}.scanner_safe"),
            failure_class,
            errors,
        );
        compare_optional_bool(
            entry.get("runtime_material").and_then(Value::as_bool),
            policy_entry.runtime_material,
            &format!("{path}.runtime_material"),
            failure_class,
            errors,
        );
    }
}

fn compare_optional_bool(
    receipt_value: Option<bool>,
    policy_value: Option<bool>,
    path: &str,
    failure_class: &str,
    errors: &mut Vec<String>,
) {
    let (Some(receipt_value), Some(policy_value)) = (receipt_value, policy_value) else {
        return;
    };
    if receipt_value != policy_value {
        errors.push(format!(
            "{path}: `{failure_class}` value `{receipt_value}` does not match {NEGATIVE_FIXTURES_TOML} `{policy_value}`"
        ));
    }
}

fn compare_optional_bool_with_source(
    left_value: Option<bool>,
    right_value: Option<bool>,
    path: &str,
    subject: &str,
    right_source: &str,
    errors: &mut Vec<String>,
) {
    let (Some(left_value), Some(right_value)) = (left_value, right_value) else {
        return;
    };
    if left_value != right_value {
        errors.push(format!(
            "{path}: `{subject}` value `{left_value}` does not match {right_source} `{right_value}`"
        ));
    }
}

fn compare_optional_string(
    left_value: Option<&str>,
    right_value: Option<&str>,
    path: &str,
    subject: &str,
    right_source: &str,
    errors: &mut Vec<String>,
) {
    let (Some(left_value), Some(right_value)) = (left_value, right_value) else {
        return;
    };
    if left_value != right_value {
        errors.push(format!(
            "{path}: `{subject}` value `{left_value}` does not match {right_source} `{right_value}`"
        ));
    }
}

fn validate_manifest_file_links<'a>(
    files: &[&'a Value],
    artifacts: &[&'a Value],
    receipts: &[&'a Value],
    errors: &mut Vec<String>,
) {
    let file_paths = files.iter().filter_map(|value| value.as_str()).collect();
    let mut declared_paths = BTreeSet::new();

    validate_manifest_declared_paths(
        "manifest.json.artifacts",
        artifacts,
        &file_paths,
        &mut declared_paths,
        errors,
    );
    validate_manifest_declared_paths(
        "manifest.json.receipts",
        receipts,
        &file_paths,
        &mut declared_paths,
        errors,
    );

    for file_path in &file_paths {
        if !declared_paths.contains(file_path) {
            errors.push(format!(
                "manifest.json.files: `{file_path}` is not declared by manifest.json.artifacts or manifest.json.receipts"
            ));
        }
    }
}

fn validate_manifest_declared_paths<'a>(
    section: &str,
    entries: &[&'a Value],
    file_paths: &BTreeSet<&'a str>,
    declared_paths: &mut BTreeSet<&'a str>,
    errors: &mut Vec<String>,
) {
    let mut section_paths = BTreeSet::new();
    for (idx, entry) in entries.iter().enumerate() {
        let path = format!("{section}[{idx}].path");
        let Some(entry_path) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !file_paths.contains(entry_path) {
            errors.push(format!(
                "{path}: `{entry_path}` is not listed in manifest.json.files"
            ));
        }
        if !section_paths.insert(entry_path) {
            errors.push(format!("{path}: duplicate path `{entry_path}`"));
        }
        if !declared_paths.insert(entry_path) {
            errors.push(format!(
                "{path}: `{entry_path}` is already declared by another manifest artifact or receipt"
            ));
        }
    }
}

fn validate_bundle_audit(schema: &Value, audit: &Value, errors: &mut Vec<String>) {
    validate_required_fields(schema, "", audit, "bundle-audit.json", errors);
    validate_object_type(audit, "bundle-audit.json", errors);
    validate_positive_integer(audit.get("version"), "bundle-audit.json.version", errors);
    validate_enum(
        audit.get("status"),
        schema.pointer("/properties/status/enum"),
        "bundle-audit.json.status",
        errors,
    );
    validate_string(
        audit.get("bundle_path"),
        "bundle-audit.json.bundle_path",
        errors,
    );
    validate_string(audit.get("profile"), "bundle-audit.json.profile", errors);
    validate_nonnegative_integer(
        audit.get("manifest_version"),
        "bundle-audit.json.manifest_version",
        errors,
    );
    if audit.get("manifest_path").and_then(Value::as_str) != Some("manifest.json") {
        errors.push("bundle-audit.json.manifest_path: expected `manifest.json`".to_string());
    }
    validate_nonnegative_integer(
        audit.get("artifact_count"),
        "bundle-audit.json.artifact_count",
        errors,
    );
    validate_nonnegative_integer(
        audit.get("receipt_count"),
        "bundle-audit.json.receipt_count",
        errors,
    );
    validate_nonnegative_integer(
        audit.get("scanner_safe_count"),
        "bundle-audit.json.scanner_safe_count",
        errors,
    );
    validate_nonnegative_integer(
        audit.get("runtime_material_count"),
        "bundle-audit.json.runtime_material_count",
        errors,
    );

    let files = validate_array(audit.get("files"), "bundle-audit.json.files", errors);
    for (idx, value) in files.iter().enumerate() {
        validate_relative_path(value, &format!("bundle-audit.json.files[{idx}]"), errors);
    }

    let artifacts = validate_array(
        audit.get("artifacts"),
        "bundle-audit.json.artifacts",
        errors,
    );
    for (idx, artifact) in artifacts.iter().enumerate() {
        let path = format!("bundle-audit.json.artifacts[{idx}]");
        validate_required_fields(schema, "/$defs/artifact", artifact, &path, errors);
        validate_object_type(artifact, &path, errors);
        validate_relative_path(
            artifact.get("path").unwrap_or(&Value::Null),
            &format!("{path}.path"),
            errors,
        );
        validate_string(artifact.get("kind"), &format!("{path}.kind"), errors);
        validate_string(artifact.get("format"), &format!("{path}.format"), errors);
        validate_bool(
            artifact.get("scanner_safe"),
            &format!("{path}.scanner_safe"),
            errors,
        );
        validate_bool(
            artifact.get("runtime_material"),
            &format!("{path}.runtime_material"),
            errors,
        );
        validate_string(
            artifact.get("description"),
            &format!("{path}.description"),
            errors,
        );
    }

    let receipts = validate_array(audit.get("receipts"), "bundle-audit.json.receipts", errors);
    for (idx, receipt) in receipts.iter().enumerate() {
        let path = format!("bundle-audit.json.receipts[{idx}]");
        validate_required_fields(schema, "/$defs/receipt", receipt, &path, errors);
        validate_object_type(receipt, &path, errors);
        validate_relative_path(
            receipt.get("path").unwrap_or(&Value::Null),
            &format!("{path}.path"),
            errors,
        );
        validate_string(receipt.get("kind"), &format!("{path}.kind"), errors);
        validate_string(receipt.get("profile"), &format!("{path}.profile"), errors);
        validate_string(
            receipt.get("description"),
            &format!("{path}.description"),
            errors,
        );
    }

    for array_name in ["missing_files", "unexpected_files"] {
        let path = format!("bundle-audit.json.{array_name}");
        let values = validate_array(audit.get(array_name), &path, errors);
        for (idx, value) in values.iter().enumerate() {
            validate_relative_path(value, &format!("{path}[{idx}]"), errors);
        }
    }

    let checks = validate_array(audit.get("checks"), "bundle-audit.json.checks", errors);
    for (idx, check) in checks.iter().enumerate() {
        let path = format!("bundle-audit.json.checks[{idx}]");
        validate_required_fields(schema, "/$defs/check", check, &path, errors);
        validate_object_type(check, &path, errors);
        validate_string(check.get("name"), &format!("{path}.name"), errors);
        validate_enum(
            check.get("status"),
            schema.pointer("/$defs/check/properties/status/enum"),
            &format!("{path}.status"),
            errors,
        );
        validate_enum(
            check.get("failure_class"),
            schema.pointer("/$defs/failure_class/enum"),
            &format!("{path}.failure_class"),
            errors,
        );
        validate_string(check.get("detail"), &format!("{path}.detail"), errors);
    }

    validate_string_array(
        audit.get("boundaries"),
        &[],
        "bundle-audit.json.boundaries",
        true,
        errors,
    );
    validate_string_array(
        audit.get("does_not_prove"),
        &[],
        "bundle-audit.json.does_not_prove",
        true,
        errors,
    );

    let artifact_count = audit
        .get("artifact_count")
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize;
    if artifact_count != artifacts.len() {
        errors.push(format!(
            "bundle-audit.json.artifact_count: expected {}, found {:?}",
            artifacts.len(),
            audit.get("artifact_count")
        ));
    }
    let receipt_count = audit
        .get("receipt_count")
        .and_then(Value::as_u64)
        .unwrap_or_default() as usize;
    if receipt_count != receipts.len() {
        errors.push(format!(
            "bundle-audit.json.receipt_count: expected {}, found {:?}",
            receipts.len(),
            audit.get("receipt_count")
        ));
    }
    let scanner_safe_count = artifacts
        .iter()
        .filter(|artifact| {
            artifact
                .get("scanner_safe")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    if audit.get("scanner_safe_count").and_then(Value::as_u64) != Some(scanner_safe_count as u64) {
        errors.push(format!(
            "bundle-audit.json.scanner_safe_count: expected {}, found {:?}",
            scanner_safe_count,
            audit.get("scanner_safe_count")
        ));
    }
    let runtime_material_count = artifacts
        .iter()
        .filter(|artifact| {
            artifact
                .get("runtime_material")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    if audit.get("runtime_material_count").and_then(Value::as_u64)
        != Some(runtime_material_count as u64)
    {
        errors.push(format!(
            "bundle-audit.json.runtime_material_count: expected {}, found {:?}",
            runtime_material_count,
            audit.get("runtime_material_count")
        ));
    }
}

fn validate_manifest_receipt_link(
    expected_profile: &str,
    manifest: &Value,
    negative_coverage: &Value,
    errors: &mut Vec<String>,
) {
    if manifest.get("profile").and_then(Value::as_str) != Some(expected_profile) {
        errors.push(format!(
            "manifest.json.profile: expected `{expected_profile}`, found {:?}",
            manifest.get("profile")
        ));
    }
    if negative_coverage.get("profile").and_then(Value::as_str) != Some(expected_profile) {
        errors.push(format!(
            "negative-coverage.json.profile: expected `{expected_profile}`, found {:?}",
            negative_coverage.get("profile")
        ));
    }
    let receipts = manifest
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has_negative_coverage = receipts.iter().any(|receipt| {
        receipt.get("path").and_then(Value::as_str) == Some("receipts/negative-coverage.json")
            && receipt.get("kind").and_then(Value::as_str) == Some("negative-coverage")
    });
    if !has_negative_coverage {
        errors.push(
            "manifest.json.receipts: missing receipts/negative-coverage.json linkage".to_string(),
        );
    }
}

fn validate_negative_coverage_manifest_link(
    expected_profile: &str,
    manifest: &Value,
    negative_coverage: &Value,
    errors: &mut Vec<String>,
) {
    let files = manifest
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let artifacts = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|artifact| {
            artifact
                .get("path")
                .and_then(Value::as_str)
                .map(|path| (path, artifact))
        })
        .collect::<BTreeMap<_, _>>();

    let coverage = negative_coverage
        .get("coverage")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (idx, entry) in coverage.iter().enumerate() {
        let path = format!("negative-coverage.json.coverage[{idx}]");
        let Some(coverage_path) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !files.contains(coverage_path) {
            errors.push(format!(
                "{path}.path: `{coverage_path}` is not listed in manifest.json.files"
            ));
        }
        let Some(artifact) = artifacts.get(coverage_path) else {
            errors.push(format!(
                "{path}.path: `{coverage_path}` is not listed in manifest.json.artifacts"
            ));
            continue;
        };
        if artifact.get("profile").and_then(Value::as_str) != Some(expected_profile) {
            errors.push(format!(
                "{path}.path: `{coverage_path}` manifest artifact profile is not `{expected_profile}`"
            ));
        }
        compare_optional_string(
            entry.get("kind").and_then(Value::as_str),
            artifact.get("kind").and_then(Value::as_str),
            &format!("{path}.kind"),
            coverage_path,
            "manifest.json.artifacts[].kind",
            errors,
        );
        compare_optional_bool_with_source(
            entry.get("scanner_safe").and_then(Value::as_bool),
            artifact.get("scanner_safe").and_then(Value::as_bool),
            &format!("{path}.scanner_safe"),
            coverage_path,
            "manifest.json.artifacts[].scanner_safe",
            errors,
        );
        compare_optional_bool_with_source(
            entry.get("runtime_material").and_then(Value::as_bool),
            artifact.get("runtime_material").and_then(Value::as_bool),
            &format!("{path}.runtime_material"),
            coverage_path,
            "manifest.json.artifacts[].runtime_material",
            errors,
        );
    }
}

fn validate_audit_manifest_link(
    expected_profile: &str,
    manifest: &Value,
    audit: &Value,
    errors: &mut Vec<String>,
) {
    if audit.get("profile").and_then(Value::as_str) != Some(expected_profile) {
        errors.push(format!(
            "bundle-audit.json.profile: expected `{expected_profile}`, found {:?}",
            audit.get("profile")
        ));
    }
    if let (Some(audit_version), Some(manifest_version)) = (
        audit.get("manifest_version").and_then(Value::as_u64),
        manifest.get("version").and_then(Value::as_u64),
    ) && audit_version != manifest_version
    {
        errors.push(format!(
            "bundle-audit.json.manifest_version: expected manifest version {manifest_version}, found {audit_version}"
        ));
    }
    let manifest_artifact_count = array_len(manifest.get("artifacts"));
    if audit.get("artifact_count").and_then(Value::as_u64) != Some(manifest_artifact_count as u64) {
        errors.push(format!(
            "bundle-audit.json.artifact_count: expected manifest artifact count {}, found {:?}",
            manifest_artifact_count,
            audit.get("artifact_count")
        ));
    }
    let manifest_receipt_count = array_len(manifest.get("receipts"));
    if audit.get("receipt_count").and_then(Value::as_u64) != Some(manifest_receipt_count as u64) {
        errors.push(format!(
            "bundle-audit.json.receipt_count: expected manifest receipt count {}, found {:?}",
            manifest_receipt_count,
            audit.get("receipt_count")
        ));
    }

    validate_audit_file_links(manifest, audit, errors);
    validate_audit_artifact_links(manifest, audit, errors);
    validate_audit_receipt_links(manifest, audit, errors);
}

fn validate_audit_file_links(manifest: &Value, audit: &Value, errors: &mut Vec<String>) {
    let manifest_files = path_set(
        manifest.get("files").and_then(Value::as_array),
        "manifest.json.files",
        errors,
    );
    let audit_files = path_set(
        audit.get("files").and_then(Value::as_array),
        "bundle-audit.json.files",
        errors,
    );

    for file_path in &manifest_files {
        if !audit_files.contains(file_path) {
            errors.push(format!(
                "bundle-audit.json.files: missing manifest file `{file_path}`"
            ));
        }
    }

    for file_path in &audit_files {
        if !manifest_files.contains(file_path) {
            errors.push(format!(
                "bundle-audit.json.files: `{file_path}` is not listed in manifest.json.files"
            ));
        }
    }
}

fn validate_audit_artifact_links(manifest: &Value, audit: &Value, errors: &mut Vec<String>) {
    let manifest_artifacts = path_map(
        manifest.get("artifacts").and_then(Value::as_array),
        "manifest.json.artifacts",
        errors,
    );
    let audit_artifacts = path_map(
        audit.get("artifacts").and_then(Value::as_array),
        "bundle-audit.json.artifacts",
        errors,
    );

    for (artifact_path, manifest_artifact) in &manifest_artifacts {
        let Some(audit_artifact) = audit_artifacts.get(artifact_path) else {
            errors.push(format!(
                "bundle-audit.json.artifacts: missing manifest artifact `{artifact_path}`"
            ));
            continue;
        };
        compare_optional_string(
            audit_artifact.get("kind").and_then(Value::as_str),
            manifest_artifact.get("kind").and_then(Value::as_str),
            &format!("bundle-audit.json.artifacts[{artifact_path}].kind"),
            artifact_path,
            "manifest.json.artifacts[].kind",
            errors,
        );
        compare_optional_string(
            audit_artifact.get("format").and_then(Value::as_str),
            manifest_artifact.get("format").and_then(Value::as_str),
            &format!("bundle-audit.json.artifacts[{artifact_path}].format"),
            artifact_path,
            "manifest.json.artifacts[].format",
            errors,
        );
        compare_optional_bool_with_source(
            audit_artifact.get("scanner_safe").and_then(Value::as_bool),
            manifest_artifact
                .get("scanner_safe")
                .and_then(Value::as_bool),
            &format!("bundle-audit.json.artifacts[{artifact_path}].scanner_safe"),
            artifact_path,
            "manifest.json.artifacts[].scanner_safe",
            errors,
        );
        let manifest_runtime_material = manifest_artifact
            .get("runtime_material")
            .and_then(Value::as_bool)
            .or_else(|| {
                manifest_artifact
                    .get("scanner_safe")
                    .and_then(Value::as_bool)
                    .map(|scanner_safe| !scanner_safe)
            });
        compare_optional_bool_with_source(
            audit_artifact
                .get("runtime_material")
                .and_then(Value::as_bool),
            manifest_runtime_material,
            &format!("bundle-audit.json.artifacts[{artifact_path}].runtime_material"),
            artifact_path,
            "manifest.json.artifacts[] runtime classification",
            errors,
        );
        compare_optional_string(
            audit_artifact.get("description").and_then(Value::as_str),
            manifest_artifact.get("description").and_then(Value::as_str),
            &format!("bundle-audit.json.artifacts[{artifact_path}].description"),
            artifact_path,
            "manifest.json.artifacts[].description",
            errors,
        );
    }

    for artifact_path in audit_artifacts.keys() {
        if !manifest_artifacts.contains_key(artifact_path) {
            errors.push(format!(
                "bundle-audit.json.artifacts: `{artifact_path}` is not listed in manifest.json.artifacts"
            ));
        }
    }
}

fn validate_audit_receipt_links(manifest: &Value, audit: &Value, errors: &mut Vec<String>) {
    let manifest_receipts = path_map(
        manifest.get("receipts").and_then(Value::as_array),
        "manifest.json.receipts",
        errors,
    );
    let audit_receipts = path_map(
        audit.get("receipts").and_then(Value::as_array),
        "bundle-audit.json.receipts",
        errors,
    );

    for (receipt_path, manifest_receipt) in &manifest_receipts {
        let Some(audit_receipt) = audit_receipts.get(receipt_path) else {
            errors.push(format!(
                "bundle-audit.json.receipts: missing manifest receipt `{receipt_path}`"
            ));
            continue;
        };
        compare_optional_string(
            audit_receipt.get("kind").and_then(Value::as_str),
            manifest_receipt.get("kind").and_then(Value::as_str),
            &format!("bundle-audit.json.receipts[{receipt_path}].kind"),
            receipt_path,
            "manifest.json.receipts[].kind",
            errors,
        );
        compare_optional_string(
            audit_receipt.get("profile").and_then(Value::as_str),
            manifest_receipt.get("profile").and_then(Value::as_str),
            &format!("bundle-audit.json.receipts[{receipt_path}].profile"),
            receipt_path,
            "manifest.json.receipts[].profile",
            errors,
        );
        compare_optional_string(
            audit_receipt.get("description").and_then(Value::as_str),
            manifest_receipt.get("description").and_then(Value::as_str),
            &format!("bundle-audit.json.receipts[{receipt_path}].description"),
            receipt_path,
            "manifest.json.receipts[].description",
            errors,
        );
    }

    for receipt_path in audit_receipts.keys() {
        if !manifest_receipts.contains_key(receipt_path) {
            errors.push(format!(
                "bundle-audit.json.receipts: `{receipt_path}` is not listed in manifest.json.receipts"
            ));
        }
    }
}

fn path_map<'a>(
    values: Option<&'a Vec<Value>>,
    section: &str,
    errors: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a Value> {
    let mut paths = BTreeMap::new();
    for (idx, value) in values.into_iter().flatten().enumerate() {
        let Some(path) = value.get("path").and_then(Value::as_str) else {
            continue;
        };
        if paths.insert(path, value).is_some() {
            errors.push(format!("{section}[{idx}].path: duplicate path `{path}`"));
        }
    }
    paths
}

fn path_set<'a>(
    values: Option<&'a Vec<Value>>,
    section: &str,
    errors: &mut Vec<String>,
) -> BTreeSet<&'a str> {
    let mut paths = BTreeSet::new();
    for (idx, value) in values.into_iter().flatten().enumerate() {
        let Some(path) = value.as_str() else {
            continue;
        };
        if !paths.insert(path) {
            errors.push(format!("{section}[{idx}]: duplicate path `{path}`"));
        }
    }
    paths
}

fn validate_required_fields(
    schema: &Value,
    pointer: &str,
    value: &Value,
    path: &str,
    errors: &mut Vec<String>,
) {
    let required = schema
        .pointer(pointer)
        .unwrap_or(schema)
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for field in required {
        let Some(field) = field.as_str() else {
            continue;
        };
        if !value
            .as_object()
            .is_some_and(|object| object.contains_key(field))
        {
            errors.push(format!("{path}: missing required field `{field}`"));
        }
    }
}

fn validate_object_type(value: &Value, path: &str, errors: &mut Vec<String>) {
    if !value.is_object() {
        errors.push(format!("{path}: expected object"));
    }
}

fn validate_string(value: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    if value.and_then(Value::as_str).is_none_or(str::is_empty) {
        errors.push(format!("{path}: expected non-empty string"));
    }
}

fn validate_positive_integer(value: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    if value.and_then(Value::as_u64).is_none_or(|value| value < 1) {
        errors.push(format!("{path}: expected positive integer"));
    }
}

fn validate_nonnegative_integer(value: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    if value.and_then(Value::as_u64).is_none() {
        errors.push(format!("{path}: expected non-negative integer"));
    }
}

fn validate_bool(value: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    if !value.is_some_and(Value::is_boolean) {
        errors.push(format!("{path}: expected boolean"));
    }
}

fn validate_array<'a>(
    value: Option<&'a Value>,
    path: &str,
    errors: &mut Vec<String>,
) -> Vec<&'a Value> {
    match value.and_then(Value::as_array) {
        Some(values) => values.iter().collect(),
        None => {
            errors.push(format!("{path}: expected array"));
            Vec::new()
        }
    }
}

fn validate_string_array(
    value: Option<&Value>,
    allowed_values: &[&str],
    path: &str,
    require_non_empty: bool,
    errors: &mut Vec<String>,
) {
    let Some(values) = value.and_then(Value::as_array) else {
        errors.push(format!("{path}: expected array"));
        return;
    };
    if require_non_empty && values.is_empty() {
        errors.push(format!("{path}: expected at least one item"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (idx, value) in values.iter().enumerate() {
        let item_path = format!("{path}[{idx}]");
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            errors.push(format!("{item_path}: expected non-empty string"));
            continue;
        };
        if !allowed_values.is_empty() && !allowed_values.contains(&value) {
            errors.push(format!("{item_path}: unsupported value `{value}`"));
        }
        if !seen.insert(value) {
            errors.push(format!("{path}: duplicate value `{value}`"));
        }
    }
}

fn validate_enum(
    value: Option<&Value>,
    enum_values: Option<&Value>,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(value) = value.and_then(Value::as_str) else {
        errors.push(format!("{path}: expected enum string"));
        return;
    };
    let allowed = enum_values
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !allowed
        .iter()
        .any(|allowed| allowed.as_str() == Some(value))
    {
        errors.push(format!("{path}: unsupported enum value `{value}`"));
    }
}

fn validate_relative_path(value: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(path_value) = value.as_str().filter(|value| !value.is_empty()) else {
        errors.push(format!("{path}: expected non-empty relative path"));
        return;
    };
    if !is_safe_relative_path(path_value) {
        errors.push(format!(
            "{path}: unsafe relative path `{}`",
            display_schema_path(path_value)
        ));
    }
}

fn validate_stable_id(value: Option<&Value>, path: &str, errors: &mut Vec<String>) {
    let Some(value) = value.and_then(Value::as_str) else {
        errors.push(format!("{path}: expected stable ID string"));
        return;
    };
    if !is_stable_id(value) {
        errors.push(format!("{path}: invalid stable ID `{value}`"));
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty()
        || path.chars().any(|ch| ch.is_control())
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.as_bytes().get(1) == Some(&b':')
    {
        return false;
    }
    path.replace('\\', "/")
        .split('/')
        .all(|component| !component.is_empty() && component != "..")
}

fn display_schema_path(path: &str) -> String {
    path.escape_default().to_string()
}

fn is_stable_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '_'))
        && !value.ends_with('_')
        && !value.contains("__")
}

fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}

fn normalize_report_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn render_bundle_schema_check_markdown(report: &BundleSchemaCheckReport) -> String {
    let mut out = String::new();
    out.push_str("# Bundle schema check\n\n");
    out.push_str(&format!(
        "- Profiles checked: {}\n",
        report.profiles_checked
    ));
    out.push_str(&format!(
        "- CI failure receipts checked: {}\n",
        report.failure_receipts_checked
    ));
    out.push_str(&format!("- Errors: {}\n\n", report.errors.len()));
    out.push_str("## Schemas\n\n");
    for schema in &report.schemas_checked {
        out.push_str(&format!("- `{schema}`\n"));
    }
    out.push_str("\n## Profiles\n\n");
    out.push_str("| Profile | Artifacts | Receipts | Negative classes | Audit receipt |\n");
    out.push_str("| --- | ---: | ---: | ---: | --- |\n");
    for profile in &report.profile_reports {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | `{}` |\n",
            profile.profile,
            profile.artifact_count,
            profile.receipt_count,
            profile.negative_count,
            profile.audit_path
        ));
    }
    out.push_str("\n## CI Failure Receipts\n\n");
    out.push_str("| Scenario | Failure class | Audit receipt |\n");
    out.push_str("| --- | --- | --- |\n");
    for failure in &report.failure_reports {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` |\n",
            failure.scenario, failure.failure_class, failure.audit_path
        ));
    }
    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for error in &report.errors {
            out.push_str(&format!("- {error}\n"));
        }
    }
    out
}

fn render_audit_receipt_examples_markdown(report: &AuditReceiptExamplesReport) -> String {
    let mut out = String::new();
    out.push_str("# Audit receipt examples check\n\n");
    out.push_str(&format!(
        "- Examples checked: {}\n",
        report.examples_checked
    ));
    out.push_str(&format!("- Schema: `{}`\n", report.schema));
    out.push_str(&format!(
        "- Examples directory: `{}`\n",
        report.examples_dir
    ));
    out.push_str(&format!("- Errors: {}\n\n", report.errors.len()));

    out.push_str("## Examples\n\n");
    out.push_str("| Failure class | Checks | Example |\n");
    out.push_str("| --- | ---: | --- |\n");
    for example in &report.examples {
        out.push_str(&format!(
            "| `{}` | {} | `{}` |\n",
            example.failure_class, example.checks, example.path
        ));
    }

    if !report.errors.is_empty() {
        out.push_str("\n## Errors\n\n");
        for error in &report.errors {
            out.push_str(&format!("- {error}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use serde_json::json;

    fn audit_schema_for_tests() -> Value {
        json!({
            "required": [
                "version",
                "status",
                "bundle_path",
                "profile",
                "manifest_version",
                "manifest_path",
                "artifact_count",
                "receipt_count",
                "scanner_safe_count",
                "runtime_material_count",
                "files",
                "artifacts",
                "receipts",
                "missing_files",
                "unexpected_files",
                "checks",
                "boundaries",
                "does_not_prove"
            ],
            "properties": {
                "status": { "enum": ["pass", "fail"] }
            },
            "$defs": {
                "artifact": {
                    "required": [
                        "path",
                        "kind",
                        "format",
                        "scanner_safe",
                        "runtime_material",
                        "description"
                    ]
                },
                "receipt": {
                    "required": ["path", "kind", "profile", "description"]
                },
                "check": {
                    "required": ["name", "status", "failure_class", "detail"],
                    "properties": {
                        "status": { "enum": ["pass", "fail"] }
                    }
                },
                "failure_class": {
                    "enum": [
                        "missing_manifest",
                        "invalid_manifest",
                        "path_escape",
                        "missing_artifact",
                        "unexpected_artifact",
                        "missing_receipt",
                        "invalid_receipt",
                        "scanner_safe_mismatch",
                        "runtime_material_mismatch",
                        "profile_validation_failed",
                        "unsupported_profile"
                    ]
                }
            }
        })
    }

    fn ci_failure_audit_for_tests(failure_class: &str) -> Value {
        json!({
            "version": 1,
            "status": "fail",
            "bundle_path": "target/uselesskey-test",
            "profile": "unknown",
            "manifest_version": 0,
            "manifest_path": "manifest.json",
            "artifact_count": 0,
            "receipt_count": 0,
            "scanner_safe_count": 0,
            "runtime_material_count": 0,
            "files": [],
            "artifacts": [],
            "receipts": [],
            "missing_files": [],
            "unexpected_files": [],
            "checks": [{
                "name": "bundle-audit",
                "status": "fail",
                "failure_class": failure_class,
                "detail": "stable failure detail"
            }],
            "boundaries": ["metadata-only"],
            "does_not_prove": ["downstream verifier correctness"]
        })
    }

    fn failure_report_for_tests(failure_class: &str) -> BundleSchemaFailureReport {
        BundleSchemaFailureReport {
            scenario: format!("ci-failure-{failure_class}"),
            audit_path: format!("target/source-of-truth/{failure_class}.json"),
            failure_class: failure_class.to_string(),
        }
    }

    fn failure_reports_for_schema(schema: &Value) -> Result<Vec<BundleSchemaFailureReport>> {
        schema
            .pointer("/$defs/failure_class/enum")
            .and_then(Value::as_array)
            .context("test schema has failure_class enum")?
            .iter()
            .map(|class| {
                let class = class.as_str().context("failure class is a string")?;
                Ok(failure_report_for_tests(class))
            })
            .collect()
    }

    fn relative_path_rejection_patterns(schema_path: &str) -> Result<Vec<Regex>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask has workspace parent")?;
        let schema: Value = serde_json::from_str(&fs::read_to_string(root.join(schema_path))?)?;
        let patterns = schema
            .pointer("/$defs/relative_path/not/anyOf")
            .and_then(Value::as_array)
            .context("relative_path not.anyOf")?;
        patterns
            .iter()
            .filter_map(|pattern| pattern.get("pattern").and_then(Value::as_str))
            .map(|pattern| Regex::new(pattern).with_context(|| format!("compile {pattern:?}")))
            .collect()
    }

    fn path_rejected_by_patterns(patterns: &[Regex], path: &str) -> bool {
        patterns.iter().any(|pattern| pattern.is_match(path))
    }

    #[test]
    fn safe_relative_path_rejects_absolute_and_parent_paths() {
        assert!(is_safe_relative_path("receipts/negative-coverage.json"));
        assert!(!is_safe_relative_path("../secret.pem"));
        assert!(!is_safe_relative_path("/tmp/secret.pem"));
        assert!(!is_safe_relative_path(r"\tmp\secret.pem"));
        assert!(!is_safe_relative_path("C:/tmp/secret.pem"));
    }

    #[test]
    fn safe_relative_path_rejects_empty_components() {
        assert!(!is_safe_relative_path("receipts//negative-coverage.json"));
        assert!(!is_safe_relative_path("receipts/"));
        assert!(!is_safe_relative_path(r"receipts\"));
    }

    #[test]
    fn safe_relative_path_rejects_control_characters() {
        assert!(!is_safe_relative_path("receipts/negative-coverage\n.json"));
        assert!(!is_safe_relative_path("receipts/negative-coverage\r.json"));
        assert!(!is_safe_relative_path("receipts/negative-coverage\t.json"));
    }

    #[test]
    fn published_relative_path_schemas_reject_cli_unsafe_shapes() -> Result<()> {
        for schema_path in [
            BUNDLE_MANIFEST_SCHEMA_JSON,
            NEGATIVE_COVERAGE_SCHEMA_JSON,
            BUNDLE_AUDIT_SCHEMA_JSON,
        ] {
            let patterns = relative_path_rejection_patterns(schema_path)?;
            for unsafe_path in [
                r"\tmp\secret.pem",
                r"\\server\share\secret.pem",
                "receipts//negative-coverage.json",
                "receipts/negative-coverage.json/",
                r"receipts\",
                "../secret.pem",
                "C:/tmp/secret.pem",
                "receipts/negative-coverage\n.json",
            ] {
                assert!(
                    path_rejected_by_patterns(&patterns, unsafe_path),
                    "{schema_path} did not reject {unsafe_path:?}"
                );
            }
            for safe_path in [
                "receipts/negative-coverage.json",
                "jwks/valid.json",
                r"receipts\negative-coverage.json",
            ] {
                assert!(
                    !path_rejected_by_patterns(&patterns, safe_path),
                    "{schema_path} rejected safe relative path {safe_path:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn relative_path_validator_escapes_control_character_diagnostics() {
        let mut errors = Vec::new();
        validate_relative_path(
            &json!("receipts/negative-coverage\n.json"),
            "negative-coverage.json.coverage[0].path",
            &mut errors,
        );

        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("receipts/negative-coverage\\n.json"));
        assert!(!errors[0].contains("receipts/negative-coverage\n.json"));
    }

    #[test]
    fn bundle_schema_output_lock_is_target_local() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let _lock = acquire_output_lock(dir.path())?;

        assert!(dir.path().join(LOCK_DIR).is_dir());
        Ok(())
    }

    #[test]
    fn negative_coverage_validator_rejects_count_drift() {
        let schema = json!({
            "required": ["receipt", "version", "profile", "negative_count", "coverage", "boundaries"],
            "properties": {
                "profile": { "enum": ["scanner-safe"] }
            },
            "$defs": {
                "coverage_entry": {
                    "required": [
                        "path",
                        "kind",
                        "failure_class",
                        "expected_failure",
                        "scanner_safe",
                        "runtime_material",
                        "description"
                    ]
                }
            }
        });
        let receipt = json!({
            "receipt": "negative-coverage",
            "version": 1,
            "profile": "scanner-safe",
            "negative_count": 2,
            "coverage": [{
                "path": "token.json",
                "kind": "token",
                "failure_class": "token_near_miss",
                "expected_failure": "policy rejects token shape",
                "scanner_safe": true,
                "runtime_material": false,
                "description": "scanner-safe token near miss"
            }],
            "boundaries": ["metadata-only"]
        });
        let mut errors = Vec::new();
        validate_negative_coverage(&schema, &receipt, &mut errors);
        assert!(errors.iter().any(|error| error.contains("negative_count")));
    }

    #[test]
    fn negative_coverage_policy_link_accepts_policy_backed_profile() {
        let receipt = json!({
            "coverage": [{
                "path": "token.json",
                "kind": "token",
                "failure_class": "token_near_miss",
                "expected_failure": "policy rejects token shape",
                "scanner_safe": true,
                "runtime_material": false,
                "description": "scanner-safe token near miss"
            }]
        });
        let mut policy = BTreeMap::new();
        policy.insert(
            "token_near_miss".to_string(),
            NegativeFixturePolicyEntry {
                stable_id: "token_near_miss".to_string(),
                status: "implemented".to_string(),
                scanner_safe: Some(true),
                runtime_material: Some(false),
                bundle_exposed: Some(true),
                bundle_profiles: vec!["scanner-safe".to_string()],
            },
        );

        let mut errors = Vec::new();
        validate_negative_coverage_policy_link("scanner-safe", &receipt, &policy, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn negative_coverage_policy_link_rejects_unbacked_or_misaligned_classes() {
        let receipt = json!({
            "coverage": [
                {
                    "path": "token.json",
                    "kind": "token",
                    "failure_class": "token_near_miss",
                    "expected_failure": "policy rejects token shape",
                    "scanner_safe": false,
                    "runtime_material": false,
                    "description": "scanner-safe token near miss"
                },
                {
                    "path": "unknown.json",
                    "kind": "token",
                    "failure_class": "missing_from_policy",
                    "expected_failure": "policy rejects token shape",
                    "scanner_safe": true,
                    "runtime_material": false,
                    "description": "unknown token near miss"
                }
            ]
        });
        let mut policy = BTreeMap::new();
        policy.insert(
            "token_near_miss".to_string(),
            NegativeFixturePolicyEntry {
                stable_id: "token_near_miss".to_string(),
                status: "implemented".to_string(),
                scanner_safe: Some(true),
                runtime_material: Some(false),
                bundle_exposed: Some(false),
                bundle_profiles: vec!["oidc".to_string()],
            },
        );

        let mut errors = Vec::new();
        validate_negative_coverage_policy_link("scanner-safe", &receipt, &policy, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("bundle_exposed=true")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("profile `scanner-safe`")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("scanner_safe")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing_from_policy")),
            "{errors:?}"
        );
    }

    #[test]
    fn manifest_file_links_accept_declared_artifacts_and_receipts() -> Result<()> {
        let manifest = json!({
            "files": ["token.json", "receipts/negative-coverage.json"],
            "artifacts": [{
                "path": "token.json"
            }],
            "receipts": [{
                "path": "receipts/negative-coverage.json"
            }]
        });
        let files = manifest["files"]
            .as_array()
            .context("expected manifest.files to be an array")?
            .iter()
            .collect::<Vec<_>>();
        let artifacts = manifest["artifacts"]
            .as_array()
            .context("expected manifest.artifacts to be an array")?
            .iter()
            .collect::<Vec<_>>();
        let receipts = manifest["receipts"]
            .as_array()
            .context("expected manifest.receipts to be an array")?
            .iter()
            .collect::<Vec<_>>();

        let mut errors = Vec::new();
        validate_manifest_file_links(&files, &artifacts, &receipts, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
        Ok(())
    }

    #[test]
    fn manifest_file_links_reject_orphan_duplicate_and_unlisted_paths() -> Result<()> {
        let manifest = json!({
            "files": ["token.json", "orphan.json"],
            "artifacts": [
                {
                    "path": "token.json"
                },
                {
                    "path": "token.json"
                },
                {
                    "path": "missing.json"
                }
            ],
            "receipts": [{
                "path": "token.json"
            }]
        });
        let files = manifest["files"]
            .as_array()
            .context("expected manifest.files to be an array")?
            .iter()
            .collect::<Vec<_>>();
        let artifacts = manifest["artifacts"]
            .as_array()
            .context("expected manifest.artifacts to be an array")?
            .iter()
            .collect::<Vec<_>>();
        let receipts = manifest["receipts"]
            .as_array()
            .context("expected manifest.receipts to be an array")?
            .iter()
            .collect::<Vec<_>>();

        let mut errors = Vec::new();
        validate_manifest_file_links(&files, &artifacts, &receipts, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("not listed in manifest.json.files")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("duplicate path")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("already declared")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("not declared")),
            "{errors:?}"
        );
        Ok(())
    }

    #[test]
    fn negative_coverage_manifest_link_accepts_manifest_declared_artifact() {
        let manifest = json!({
            "profile": "scanner-safe",
            "files": ["token.json"],
            "artifacts": [{
                "path": "token.json",
                "kind": "token",
                "profile": "scanner-safe",
                "scanner_safe": true,
                "runtime_material": false
            }]
        });
        let receipt = json!({
            "coverage": [{
                "path": "token.json",
                "kind": "token",
                "failure_class": "token_near_miss",
                "scanner_safe": true,
                "runtime_material": false
            }]
        });

        let mut errors = Vec::new();
        validate_negative_coverage_manifest_link("scanner-safe", &manifest, &receipt, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn negative_coverage_manifest_link_rejects_missing_or_misaligned_artifacts() {
        let manifest = json!({
            "profile": "scanner-safe",
            "files": ["token.json"],
            "artifacts": [{
                "path": "token.json",
                "kind": "jwt",
                "profile": "oidc",
                "scanner_safe": false,
                "runtime_material": true
            }]
        });
        let receipt = json!({
            "coverage": [
                {
                    "path": "token.json",
                    "kind": "token",
                    "failure_class": "token_near_miss",
                    "scanner_safe": true,
                    "runtime_material": false
                },
                {
                    "path": "missing.json",
                    "kind": "token",
                    "failure_class": "token_missing",
                    "scanner_safe": true,
                    "runtime_material": false
                }
            ]
        });

        let mut errors = Vec::new();
        validate_negative_coverage_manifest_link("scanner-safe", &manifest, &receipt, &mut errors);

        assert!(
            errors
                .iter()
                .any(|error| error.contains("manifest.json.files")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("manifest.json.artifacts")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("profile")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("kind")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("scanner_safe")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("runtime_material")),
            "{errors:?}"
        );
    }

    #[test]
    fn audit_manifest_link_accepts_matching_artifacts_and_receipts() {
        let manifest = json!({
            "version": 1,
            "profile": "scanner-safe",
            "files": ["token.json", "receipts/negative-coverage.json"],
            "artifacts": [{
                "path": "token.json",
                "kind": "token",
                "format": "json",
                "scanner_safe": true,
                "description": "scanner-safe token"
            }],
            "receipts": [{
                "path": "receipts/negative-coverage.json",
                "kind": "negative-coverage",
                "profile": "scanner-safe",
                "description": "negative coverage"
            }]
        });
        let audit = json!({
            "profile": "scanner-safe",
            "manifest_version": 1,
            "artifact_count": 1,
            "receipt_count": 1,
            "files": ["token.json", "receipts/negative-coverage.json"],
            "artifacts": [{
                "path": "token.json",
                "kind": "token",
                "format": "json",
                "scanner_safe": true,
                "runtime_material": false,
                "description": "scanner-safe token"
            }],
            "receipts": [{
                "path": "receipts/negative-coverage.json",
                "kind": "negative-coverage",
                "profile": "scanner-safe",
                "description": "negative coverage"
            }]
        });

        let mut errors = Vec::new();
        validate_audit_manifest_link("scanner-safe", &manifest, &audit, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn audit_manifest_link_rejects_metadata_drift() {
        let manifest = json!({
            "version": 1,
            "profile": "scanner-safe",
            "files": [
                "token.json",
                "receipts/negative-coverage.json",
                "missing-from-audit.json"
            ],
            "artifacts": [{
                "path": "token.json",
                "kind": "token",
                "format": "json",
                "scanner_safe": true,
                "description": "scanner-safe token"
            }],
            "receipts": [{
                "path": "receipts/negative-coverage.json",
                "kind": "negative-coverage",
                "profile": "scanner-safe",
                "description": "negative coverage"
            }]
        });
        let audit = json!({
            "profile": "scanner-safe",
            "manifest_version": 2,
            "artifact_count": 2,
            "receipt_count": 2,
            "files": [
                "token.json",
                "extra-file.json",
                "extra-file.json"
            ],
            "artifacts": [
                {
                    "path": "token.json",
                    "kind": "jwt",
                    "format": "pem",
                    "scanner_safe": false,
                    "runtime_material": true,
                    "description": "drifted token"
                },
                {
                    "path": "extra.json",
                    "kind": "token",
                    "format": "json",
                    "scanner_safe": true,
                    "runtime_material": false,
                    "description": "extra token"
                }
            ],
            "receipts": [
                {
                    "path": "receipts/negative-coverage.json",
                    "kind": "scanner-safety",
                    "profile": "runtime",
                    "description": "wrong receipt"
                },
                {
                    "path": "receipts/extra.json",
                    "kind": "scanner-safety",
                    "profile": "scanner-safe",
                    "description": "extra receipt"
                }
            ]
        });

        let mut errors = Vec::new();
        validate_audit_manifest_link("scanner-safe", &manifest, &audit, &mut errors);

        for expected in [
            "artifact_count",
            "receipt_count",
            "manifest_version",
            "kind",
            "format",
            "scanner_safe",
            "runtime_material",
            "description",
            "extra.json",
            "missing-from-audit.json",
            "extra-file.json",
            "duplicate path",
            "profile",
            "receipts/extra.json",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "missing `{expected}` in {errors:?}"
            );
        }
    }

    #[test]
    fn bundle_audit_validator_rejects_count_drift() {
        let schema = audit_schema_for_tests();
        let audit = json!({
            "version": 1,
            "status": "pass",
            "bundle_path": "target/uselesskey-test",
            "profile": "scanner-safe",
            "manifest_version": 1,
            "manifest_path": "manifest.json",
            "artifact_count": 2,
            "receipt_count": 1,
            "scanner_safe_count": 1,
            "runtime_material_count": 1,
            "files": ["tokens/near-miss.json"],
            "artifacts": [{
                "path": "tokens/near-miss.json",
                "kind": "token",
                "format": "json-manifest",
                "scanner_safe": true,
                "runtime_material": false,
                "description": "scanner-safe token near miss"
            }],
            "receipts": [{
                "path": "receipts/negative-coverage.json",
                "kind": "negative-coverage",
                "profile": "scanner-safe",
                "description": "negative coverage"
            }],
            "missing_files": [],
            "unexpected_files": [],
            "checks": [{
                "name": "artifact-content",
                "status": "pass",
                "failure_class": "missing_artifact",
                "detail": "checked"
            }],
            "boundaries": ["metadata-only"],
            "does_not_prove": ["production security"]
        });
        let mut errors = Vec::new();
        validate_bundle_audit(&schema, &audit, &mut errors);
        assert!(errors.iter().any(|error| error.contains("artifact_count")));
        assert!(
            errors
                .iter()
                .any(|error| error.contains("runtime_material_count"))
        );
    }

    #[test]
    fn bundle_audit_validator_rejects_unsafe_relative_paths() {
        let schema = audit_schema_for_tests();
        let audit = json!({
            "version": 1,
            "status": "pass",
            "bundle_path": "target/uselesskey-test",
            "profile": "scanner-safe",
            "manifest_version": 1,
            "manifest_path": "manifest.json",
            "artifact_count": 1,
            "receipt_count": 1,
            "scanner_safe_count": 1,
            "runtime_material_count": 0,
            "files": ["tokens/near-miss\n.json"],
            "artifacts": [{
                "path": "../tokens/near-miss.json",
                "kind": "token",
                "format": "json-manifest",
                "scanner_safe": true,
                "runtime_material": false,
                "description": "scanner-safe token near miss"
            }],
            "receipts": [{
                "path": "C:/receipts/negative-coverage.json",
                "kind": "negative-coverage",
                "profile": "scanner-safe",
                "description": "negative coverage"
            }],
            "missing_files": ["/missing.json"],
            "unexpected_files": ["\\\\extra.json"],
            "checks": [{
                "name": "path-containment",
                "status": "pass",
                "failure_class": "path_escape",
                "detail": "checked"
            }],
            "boundaries": ["metadata-only"],
            "does_not_prove": ["production security"]
        });
        let mut errors = Vec::new();
        validate_bundle_audit(&schema, &audit, &mut errors);

        for expected in [
            "bundle-audit.json.files[0]",
            "tokens/near-miss\\n.json",
            "bundle-audit.json.artifacts[0].path",
            "../tokens/near-miss.json",
            "bundle-audit.json.receipts[0].path",
            "C:/receipts/negative-coverage.json",
            "bundle-audit.json.missing_files[0]",
            "/missing.json",
            "bundle-audit.json.unexpected_files[0]",
            "\\\\extra.json",
        ] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "missing `{expected}` in {errors:?}"
            );
        }
    }

    #[test]
    fn failure_class_coverage_accepts_schema_classes_with_generated_receipts() -> Result<()> {
        let schema = audit_schema_for_tests();
        let reports = failure_reports_for_schema(&schema)?;
        let mut errors = Vec::new();

        validate_failure_class_coverage(&schema, &reports, &mut errors);

        assert!(errors.is_empty(), "{errors:?}");
        Ok(())
    }

    #[test]
    fn failure_class_coverage_rejects_missing_generated_receipt() {
        let schema = audit_schema_for_tests();
        let reports = vec![failure_report_for_tests("unsupported_profile")];
        let mut errors = Vec::new();

        validate_failure_class_coverage(&schema, &reports, &mut errors);

        assert!(
            errors.iter().any(|error| {
                error.contains("bundle-audit failure_class `missing_manifest`")
                    && error.contains("no generated CI failure receipt")
            }),
            "{errors:?}"
        );
    }

    #[test]
    fn failure_class_coverage_rejects_receipt_class_outside_schema() -> Result<()> {
        let schema = audit_schema_for_tests();
        let mut reports = failure_reports_for_schema(&schema)?;
        reports.push(failure_report_for_tests("future_failure"));
        let mut errors = Vec::new();

        validate_failure_class_coverage(&schema, &reports, &mut errors);

        assert!(
            errors.iter().any(|error| {
                error.contains("generated CI failure receipt class `future_failure`")
                    && error.contains("not listed in bundle-audit schema")
            }),
            "{errors:?}"
        );
        Ok(())
    }

    #[test]
    fn failure_receipt_validator_accepts_ci_failure_shapes() {
        let schema = audit_schema_for_tests();
        for failure_class in [
            "missing_manifest",
            "invalid_manifest",
            "path_escape",
            "missing_artifact",
            "unexpected_artifact",
            "missing_receipt",
            "invalid_receipt",
            "scanner_safe_mismatch",
            "runtime_material_mismatch",
            "profile_validation_failed",
            "unsupported_profile",
        ] {
            let audit = ci_failure_audit_for_tests(failure_class);
            let mut errors = Vec::new();
            validate_failure_receipt("ci-failure", &audit, failure_class, &schema, &mut errors);

            assert!(errors.is_empty(), "{failure_class}: {errors:?}");
        }
    }

    #[test]
    fn failure_receipt_validator_rejects_wrong_failure_class() {
        let schema = audit_schema_for_tests();
        let audit = ci_failure_audit_for_tests("unsupported_profile");
        let mut errors = Vec::new();
        validate_failure_receipt(
            "ci-failure-missing-manifest",
            &audit,
            "missing_manifest",
            &schema,
            &mut errors,
        );

        assert!(
            errors.iter().any(|error| {
                error.contains("expected failure_class `missing_manifest`")
                    && error.contains("unsupported_profile")
            }),
            "{errors:?}"
        );
    }

    #[test]
    fn audit_receipt_example_validator_accepts_minimal_failure_example() {
        let schema = audit_schema_for_tests();
        let mut errors = Vec::new();
        let schema_classes = bundle_audit_failure_classes(&schema, &mut errors);
        let audit = ci_failure_audit_for_tests("missing_manifest");

        validate_audit_receipt_example(
            "examples/audit-receipts/missing_manifest.json",
            "missing_manifest",
            &audit,
            &schema,
            &schema_classes,
            &mut errors,
        );

        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn audit_receipt_examples_markdown_names_examples_and_errors() {
        let report = AuditReceiptExamplesReport {
            schema_version: 1,
            examples_checked: 1,
            schema: BUNDLE_AUDIT_SCHEMA_JSON.to_string(),
            examples_dir: AUDIT_RECEIPT_EXAMPLES_DIR.to_string(),
            examples: vec![AuditReceiptExampleReport {
                path: "examples/audit-receipts/missing_manifest.json".to_string(),
                failure_class: "missing_manifest".to_string(),
                checks: 1,
            }],
            errors: vec!["example error".to_string()],
        };

        let markdown = render_audit_receipt_examples_markdown(&report);

        for expected in [
            "Examples checked: 1",
            BUNDLE_AUDIT_SCHEMA_JSON,
            AUDIT_RECEIPT_EXAMPLES_DIR,
            "`missing_manifest`",
            "`examples/audit-receipts/missing_manifest.json`",
            "example error",
        ] {
            assert!(
                markdown.contains(expected),
                "missing `{expected}` in {markdown}"
            );
        }
    }

    #[test]
    fn audit_receipt_examples_report_writer_emits_json_and_markdown() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let report = AuditReceiptExamplesReport {
            schema_version: 1,
            examples_checked: 1,
            schema: BUNDLE_AUDIT_SCHEMA_JSON.to_string(),
            examples_dir: AUDIT_RECEIPT_EXAMPLES_DIR.to_string(),
            examples: vec![AuditReceiptExampleReport {
                path: "examples/audit-receipts/missing_manifest.json".to_string(),
                failure_class: "missing_manifest".to_string(),
                checks: 1,
            }],
            errors: Vec::new(),
        };

        write_audit_receipt_examples_report_at(dir.path(), &report)?;

        let json_path = dir
            .path()
            .join(AUDIT_RECEIPT_REPORT_DIR)
            .join(AUDIT_RECEIPT_REPORT_JSON);
        let markdown_path = dir
            .path()
            .join(AUDIT_RECEIPT_REPORT_DIR)
            .join(AUDIT_RECEIPT_REPORT_MD);
        let json: Value = serde_json::from_str(&fs::read_to_string(&json_path)?)?;
        let markdown = fs::read_to_string(&markdown_path)?;

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["examples_checked"], 1);
        assert_eq!(json["schema"], BUNDLE_AUDIT_SCHEMA_JSON);
        assert_eq!(json["examples"][0]["failure_class"], "missing_manifest");
        assert!(markdown.contains("Examples checked: 1"));
        assert!(markdown.contains("`missing_manifest`"));
        Ok(())
    }

    #[test]
    fn audit_receipt_example_coverage_rejects_missing_schema_class() {
        let schema = audit_schema_for_tests();
        let mut errors = Vec::new();
        let schema_classes = bundle_audit_failure_classes(&schema, &mut errors);
        let example_classes = BTreeSet::from(["missing_manifest".to_string()]);

        validate_audit_receipt_example_coverage(&schema_classes, &example_classes, &mut errors);

        assert!(
            errors.iter().any(|error| {
                error.contains("bundle-audit failure_class `invalid_manifest`")
                    && error.contains("no committed audit receipt example")
            }),
            "{errors:?}"
        );
    }

    #[test]
    fn audit_receipt_example_validator_rejects_extra_payload_fields() {
        let schema = audit_schema_for_tests();
        let mut errors = Vec::new();
        let schema_classes = bundle_audit_failure_classes(&schema, &mut errors);
        let mut audit = ci_failure_audit_for_tests("missing_manifest");
        audit["payload"] = json!("raw webhook request body");

        validate_audit_receipt_example(
            "examples/audit-receipts/missing_manifest.json",
            "missing_manifest",
            &audit,
            &schema,
            &schema_classes,
            &mut errors,
        );

        assert!(
            errors
                .iter()
                .any(|error| error.contains("unsupported field `payload`")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("forbidden raw-material field name")),
            "{errors:?}"
        );
    }

    #[test]
    fn audit_receipt_material_guard_rejects_payload_markers() {
        let mut errors = Vec::new();
        validate_no_audit_receipt_material(
            "bundle-audit.json",
            &json!({
                "checks": [{
                    "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
                }],
                "jwk": {
                    "k": "raw-symmetric-key"
                },
                "private": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
            }),
            &mut errors,
        );

        assert!(
            errors
                .iter()
                .any(|error| error.contains("JWT-shaped value")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("forbidden raw-material field name")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("forbidden payload marker")),
            "{errors:?}"
        );
    }
}

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uselesskey_cli::{
    ArtifactType as ExportArtifactType, ExportArtifact, ManifestArtifact,
    emit_include_bytes_module, load_materialize_manifest, materialize_manifest_to_dir,
    render_k8s_secret_yaml, render_vault_kv_json,
};
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_jwk::NegativeJwks;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};
use uselesskey_webhook::{WebhookFactoryExt, WebhookPayloadSpec};
use uselesskey_x509::{ChainNegative, ChainSpec, X509Chain, X509FactoryExt, X509Spec};

#[derive(Parser, Debug)]
#[command(
    name = "uselesskey",
    about = "Generate deterministic test fixtures with metadata-only audit receipts",
    after_help = "Start here:
  uselesskey doctor
  uselesskey profiles
  uselesskey bundle --profile webhook --out target/uselesskey-webhook
  uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit

Boundaries:
  Installed CLI commands generate, verify, inspect, and audit local fixtures.
  Repo public-claim proof is separate from installed CLI setup."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Generate one fixture artifact")]
    Generate(GenerateArgs),
    #[command(about = "List bundle profiles and copyable installed commands")]
    Profiles(ProfilesArgs),
    #[command(about = "Explain one bundle profile and its proof boundary")]
    Profile(ProfileArgs),
    #[command(about = "Generate a deterministic fixture bundle")]
    Bundle(BundleArgs),
    #[command(about = "Check a bundle manifest and listed files")]
    VerifyBundle(VerifyBundleArgs),
    #[command(about = "Print a quick human summary of bundle metadata")]
    InspectBundle(InspectBundleArgs),
    #[command(about = "Emit metadata-only bundle audit receipts for reviewers or CI")]
    AuditBundle(AuditBundleArgs),
    #[command(about = "Check installed CLI readiness and safe default output paths")]
    Doctor(DoctorArgs),
    #[command(about = "Export generated fixtures into platform-friendly shapes")]
    Export(ExportArgs),
    #[command(about = "Inspect a materialization manifest")]
    Inspect(InspectArgs),
    #[command(about = "Materialize fixtures from a reviewed manifest")]
    Materialize(MaterializeArgs),
    #[command(about = "Verify a materialization manifest")]
    Verify(VerifyArgs),
}

#[derive(clap::Args, Debug)]
struct ProfilesArgs {
    #[arg(long)]
    explain: bool,
}

#[derive(clap::Args, Debug)]
struct ProfileArgs {
    profile: BundleProfile,
    #[arg(long)]
    explain: bool,
}

#[derive(clap::Args, Debug)]
struct GenerateArgs {
    kind: Kind,
    #[arg(long)]
    seed: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    format: Format,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(after_help = "Examples:
  uselesskey bundle --profile webhook --out target/uselesskey-webhook
  uselesskey verify-bundle target/uselesskey-webhook
  uselesskey inspect-bundle target/uselesskey-webhook
  uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit

Boundary:
  bundle writes test fixtures; keep generated payloads under target/ unless
  your project has reviewed another output path.")]
struct BundleArgs {
    /// Deterministic seed for this bundle. This is test input, not a secret.
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    seed: String,
    /// Stable label used in deterministic artifact identity.
    #[arg(long, default_value = "bundle")]
    label: String,
    /// Preferred artifact format when the profile supports multiple formats.
    #[arg(long, default_value = "jwk")]
    format: Format,
    /// Bundle profile to generate.
    #[arg(long, default_value = "scanner-safe")]
    profile: BundleProfile,
    /// Output directory for the generated bundle.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Explain the profile, generated files, audit path, and boundary without writing files.
    #[arg(long)]
    explain: bool,
}

#[derive(clap::Args, Debug)]
#[command(group(
    ArgGroup::new("verify_bundle_input")
        .required(true)
        .args(["bundle_dir", "path"])
))]
struct VerifyBundleArgs {
    /// Bundle directory to verify.
    #[arg(value_name = "BUNDLE_DIR")]
    bundle_dir: Option<PathBuf>,
    /// Bundle directory to verify. `--bundle-dir` remains available as an alias.
    #[arg(long = "path", visible_alias = "bundle-dir", value_name = "BUNDLE_DIR")]
    path: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(group(
    ArgGroup::new("inspect_bundle_input")
        .required(true)
        .args(["bundle_dir", "path"])
))]
struct InspectBundleArgs {
    /// Bundle directory to inspect.
    #[arg(value_name = "BUNDLE_DIR")]
    bundle_dir: Option<PathBuf>,
    /// Bundle directory to inspect. `--bundle-dir` remains available as an alias.
    #[arg(long = "path", visible_alias = "bundle-dir", value_name = "BUNDLE_DIR")]
    path: Option<PathBuf>,
    /// Optional path for writing the human summary.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
#[command(after_help = "Examples:
  uselesskey audit-bundle target/uselesskey-webhook --out target/uselesskey-webhook-audit
  uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit
  uselesskey audit-bundle target/uselesskey-webhook --ci --expect-profile webhook --policy strict --out target/uselesskey-webhook-audit
  uselesskey audit-bundle target/uselesskey-webhook --summary

Boundary:
  audit-bundle checks local bundle consistency and metadata labels. It does
  not prove production security, provider compatibility, or broader repo public
  claims by itself.

CI:
  Combine --ci with --out to keep bundle-audit.json and bundle-audit.md as
  uploadable metadata-only receipts for passing audits and stable policy
  failures.")]
#[command(group(
    ArgGroup::new("audit_bundle_input")
        .required(true)
        .args(["bundle_dir", "path"])
))]
struct AuditBundleArgs {
    /// Bundle directory to audit.
    #[arg(value_name = "BUNDLE_DIR")]
    bundle_dir: Option<PathBuf>,
    /// Bundle directory to audit. `--bundle-dir` remains available as an alias.
    #[arg(long = "path", visible_alias = "bundle-dir", value_name = "BUNDLE_DIR")]
    path: Option<PathBuf>,
    /// Directory for metadata-only Markdown and JSON audit receipts.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Output format when writing to stdout.
    #[arg(long, default_value = "markdown")]
    format: AuditOutputFormat,
    /// Emit CI-oriented JSON and exit non-zero on stable audit failure classes.
    #[arg(long, conflicts_with = "summary")]
    ci: bool,
    /// Require the audited manifest profile to match the CI job's expected profile.
    #[arg(long, value_name = "PROFILE")]
    expect_profile: Option<String>,
    /// Apply a built-in audit policy preset.
    #[arg(long, value_enum)]
    policy: Option<AuditPolicy>,
    /// Print a compact human summary for terminals or CI logs.
    #[arg(long)]
    summary: bool,
}

impl VerifyBundleArgs {
    fn bundle_dir(&self) -> Result<&Path> {
        self.bundle_dir
            .as_deref()
            .or(self.path.as_deref())
            .context("clap requires a bundle directory")
    }
}

impl InspectBundleArgs {
    fn bundle_dir(&self) -> Result<&Path> {
        self.bundle_dir
            .as_deref()
            .or(self.path.as_deref())
            .context("clap requires a bundle directory")
    }
}

impl AuditBundleArgs {
    fn bundle_dir(&self) -> Result<&Path> {
        self.bundle_dir
            .as_deref()
            .or(self.path.as_deref())
            .context("clap requires a bundle directory")
    }
}

#[cfg(test)]
mod bundle_input_arg_tests {
    use super::*;

    #[test]
    fn verify_bundle_accepts_positional_path_and_aliases() -> Result<()> {
        for argv in [
            vec!["uselesskey", "verify-bundle", "target/uselesskey-oidc"],
            vec![
                "uselesskey",
                "verify-bundle",
                "--path",
                "target/uselesskey-oidc",
            ],
            vec![
                "uselesskey",
                "verify-bundle",
                "--bundle-dir",
                "target/uselesskey-oidc",
            ],
        ] {
            let cli = Cli::try_parse_from(argv)?;
            let Commands::VerifyBundle(args) = cli.command else {
                bail!("expected verify-bundle command");
            };

            assert_eq!(args.bundle_dir()?, Path::new("target/uselesskey-oidc"));
        }

        Ok(())
    }

    #[test]
    fn inspect_bundle_accepts_positional_path_and_aliases() -> Result<()> {
        for argv in [
            vec!["uselesskey", "inspect-bundle", "target/uselesskey-oidc"],
            vec![
                "uselesskey",
                "inspect-bundle",
                "--path",
                "target/uselesskey-oidc",
            ],
            vec![
                "uselesskey",
                "inspect-bundle",
                "--bundle-dir",
                "target/uselesskey-oidc",
            ],
        ] {
            let cli = Cli::try_parse_from(argv)?;
            let Commands::InspectBundle(args) = cli.command else {
                bail!("expected inspect-bundle command");
            };

            assert_eq!(args.bundle_dir()?, Path::new("target/uselesskey-oidc"));
        }

        Ok(())
    }

    #[test]
    fn audit_bundle_accepts_path_aliases_with_ci_policy_flags() -> Result<()> {
        for argv in [
            vec![
                "uselesskey",
                "audit-bundle",
                "target/uselesskey-oidc",
                "--ci",
                "--expect-profile",
                "oidc",
                "--policy",
                "strict",
            ],
            vec![
                "uselesskey",
                "audit-bundle",
                "--path",
                "target/uselesskey-oidc",
                "--ci",
                "--expect-profile",
                "oidc",
                "--policy",
                "strict",
            ],
            vec![
                "uselesskey",
                "audit-bundle",
                "--bundle-dir",
                "target/uselesskey-oidc",
                "--ci",
                "--expect-profile",
                "oidc",
                "--policy",
                "strict",
            ],
        ] {
            let cli = Cli::try_parse_from(argv)?;
            let Commands::AuditBundle(args) = cli.command else {
                bail!("expected audit-bundle command");
            };

            assert_eq!(args.bundle_dir()?, Path::new("target/uselesskey-oidc"));
            assert!(args.ci);
            assert_eq!(args.expect_profile.as_deref(), Some("oidc"));
            assert_eq!(args.policy, Some(AuditPolicy::Strict));
        }

        Ok(())
    }
}

#[derive(clap::Args, Debug)]
#[command(after_help = "Examples:
  uselesskey doctor
  uselesskey doctor --format json

Checks installed CLI concerns only: version, working directory, target write
access, safe default profile paths, JSON output, and known profiles.")]
struct DoctorArgs {
    /// Doctor output format.
    #[arg(long, default_value = "text")]
    format: DoctorOutputFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuditOutputFormat {
    Markdown,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum AuditPolicy {
    Strict,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DoctorOutputFormat {
    Text,
    Json,
}

#[derive(clap::Args, Debug)]
struct ExportArgs {
    #[command(subcommand)]
    target: ExportTarget,
}

#[derive(Subcommand, Debug)]
enum ExportTarget {
    K8s(ExportK8sArgs),
    VaultKvJson(ExportVaultKvJsonArgs),
}

#[derive(clap::Args, Debug)]
struct ExportK8sArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    bundle_dir: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long)]
    namespace: Option<String>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ExportVaultKvJsonArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    bundle_dir: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct InspectArgs {
    #[arg(long)]
    format: Format,
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct MaterializeArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    out_dir: Option<PathBuf>,
    #[arg(long)]
    emit_rs: Option<PathBuf>,
    #[arg(long, hide = true)]
    check: bool,
}

#[derive(clap::Args, Debug)]
struct VerifyArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    out_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Kind {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Jwk,
    Jwks,
}

impl Kind {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ecdsa => "ecdsa",
            Self::Ed25519 => "ed25519",
            Self::Hmac => "hmac",
            Self::Token => "token",
            Self::X509 => "x509",
            Self::Jwk => "jwk",
            Self::Jwks => "jwks",
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Pem,
    Der,
    Jwk,
    Jwks,
    #[value(name = "json-manifest")]
    JsonManifest,
    #[value(name = "bundle-dir")]
    BundleDir,
}

impl Format {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::Pem => "pem",
            Self::Der => "der",
            Self::Jwk => "jwk",
            Self::Jwks => "jwks",
            Self::JsonManifest => "json-manifest",
            Self::BundleDir => "bundle-dir",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BundleProfile {
    ScannerSafe,
    Oidc,
    Tls,
    Webhook,
    Runtime,
}

impl BundleProfile {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Tls => "tls",
            Self::Webhook => "webhook",
            Self::Runtime => "runtime",
        }
    }

    const fn output_dir_hint(self) -> &'static str {
        match self {
            Self::ScannerSafe => "target/uselesskey-bundle",
            Self::Oidc => "target/uselesskey-oidc",
            Self::Tls => "target/uselesskey-tls",
            Self::Webhook => "target/uselesskey-webhook",
            Self::Runtime => "target/uselesskey-runtime",
        }
    }
}

const DISCOVERABLE_PROFILES: [BundleProfile; 5] = [
    BundleProfile::ScannerSafe,
    BundleProfile::Tls,
    BundleProfile::Oidc,
    BundleProfile::Webhook,
    BundleProfile::Runtime,
];

#[derive(Debug)]
enum Artifact {
    Text(String),
    Binary(Vec<u8>),
    Json(serde_json::Value),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate(args) => run_generate(args),
        Commands::Profiles(args) => run_profiles(args),
        Commands::Profile(args) => run_profile(args),
        Commands::Bundle(args) => run_bundle(args),
        Commands::VerifyBundle(args) => run_verify_bundle(args),
        Commands::InspectBundle(args) => run_inspect_bundle(args),
        Commands::AuditBundle(args) => run_audit_bundle(args),
        Commands::Doctor(args) => run_doctor(args),
        Commands::Export(args) => run_export(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Materialize(args) => run_materialize(args),
        Commands::Verify(args) => run_verify(args),
    }
}

fn run_doctor(args: DoctorArgs) -> Result<()> {
    let report = build_doctor_report();
    match args.format {
        DoctorOutputFormat::Text => {
            emit_artifact(&Artifact::Text(render_doctor_report(&report)), None)
        }
        DoctorOutputFormat::Json => emit_artifact(&Artifact::Json(json!(report)), None),
    }
}

fn run_profiles(args: ProfilesArgs) -> Result<()> {
    emit_artifact(&Artifact::Text(render_profiles(args.explain)), None)
}

fn run_profile(args: ProfileArgs) -> Result<()> {
    let report = if args.explain {
        render_profile_explanation(args.profile)
    } else {
        render_profile_summary(args.profile)
    };
    emit_artifact(&Artifact::Text(report), None)
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let fx = Factory::deterministic_from_str(&args.seed);
    let artifact = generate_artifact(&fx, args.kind, &args.label, args.format)?;
    emit_artifact(&artifact, args.out.as_deref())
}

fn run_bundle(args: BundleArgs) -> Result<()> {
    if args.explain {
        return emit_artifact(
            &Artifact::Text(render_profile_explanation(args.profile)),
            None,
        );
    }

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}-bundle", args.label)));
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create bundle directory {}", out_dir.display()))?;

    let fx = Factory::deterministic_from_str(&args.seed);
    let mut files = Vec::new();
    let mut artifacts = Vec::new();
    for entry in bundle_entries(args.profile) {
        let bundle_format = entry.preferred_format(args.format, args.profile);
        let artifact =
            generate_bundle_entry_artifact(&fx, entry, &args.label, bundle_format, args.profile)
                .with_context(|| format!("failed to generate {}", entry.name()))?;
        let file_name = entry.file_name(bundle_format, &artifact);
        let file = out_dir.join(&file_name);
        write_artifact_to_path(&artifact, &file)?;
        files.push(file_name.clone());
        artifacts.push(bundle_artifact_record(
            entry,
            bundle_format,
            &file_name,
            args.profile,
        ));
    }
    let fixture_files = files.clone();
    let receipts = bundle_receipt_records(args.profile);
    for receipt in &receipts {
        let receipt_artifact = generate_bundle_receipt_artifact(
            &receipt.kind,
            &args.seed,
            &args.label,
            args.format,
            args.profile,
            &fixture_files,
            &artifacts,
        )?;
        let file = out_dir.join(&receipt.path);
        write_artifact_to_path(&receipt_artifact, &file)?;
        files.push(receipt.path.clone());
    }

    let manifest = BundleManifest {
        version: 1,
        profile: args.profile.manifest_name().to_string(),
        seed: args.seed,
        label: args.label,
        format: args.format.manifest_name().to_string(),
        files,
        artifacts,
        receipts,
    };
    let manifest_path = out_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    emit_artifact(
        &Artifact::Json(json!({"bundle_dir": out_dir, "manifest": manifest})),
        None,
    )
}

fn run_verify_bundle(args: VerifyBundleArgs) -> Result<()> {
    let bundle_dir = args.bundle_dir()?.to_path_buf();
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    let files = verify_bundle_manifest(&bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", bundle_dir.display()))?;

    emit_artifact(
        &Artifact::Json(json!({
            "verify_bundle": {
                "status": "ok",
                "bundle_dir": bundle_dir,
                "manifest": manifest_path,
                "count": files.len(),
                "files": files,
            }
        })),
        None,
    )
}

fn run_inspect_bundle(args: InspectBundleArgs) -> Result<()> {
    let bundle_dir = args.bundle_dir()?.to_path_buf();
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    let files = verify_bundle_manifest(&bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", bundle_dir.display()))?;
    let summary = render_bundle_inspection_summary(&manifest, files.len());

    emit_artifact(&Artifact::Text(summary), args.out.as_deref())
}

fn run_audit_bundle(args: AuditBundleArgs) -> Result<()> {
    if args.ci && args.summary {
        bail!("audit-bundle --summary cannot be combined with --ci");
    }

    if args.ci {
        return run_audit_bundle_ci(args);
    }

    let bundle_dir = args.bundle_dir()?.to_path_buf();
    let audit = match build_bundle_audit(&bundle_dir) {
        Ok(audit) => audit,
        Err(err) => {
            let diagnostic = bundle_audit_failure_diagnostic(&err);
            bail!(
                "audit failed: {}: {}",
                diagnostic.failure_class,
                diagnostic.detail
            );
        }
    };
    if let Some(diagnostic) = bundle_audit_policy_failure(&audit, &args) {
        bail!(
            "audit policy failed: {}: {}",
            diagnostic.failure_class,
            diagnostic.detail
        );
    }

    if let Some(out_dir) = args.out.as_deref() {
        let (json_path, md_path) = write_bundle_audit_receipts(&audit, out_dir)?;
        if args.summary {
            return emit_artifact(
                &Artifact::Text(render_bundle_audit_summary(&audit, Some(out_dir))),
                None,
            );
        }
        return emit_artifact(
            &Artifact::Json(json!({
                "audit_bundle": {
                    "status": audit.status,
                    "bundle_dir": audit.bundle_path,
                    "out": out_dir,
                    "json": json_path,
                    "markdown": md_path,
                }
            })),
            None,
        );
    }

    if args.summary {
        return emit_artifact(
            &Artifact::Text(render_bundle_audit_summary(&audit, None)),
            None,
        );
    }

    match args.format {
        AuditOutputFormat::Markdown => {
            emit_artifact(&Artifact::Text(render_bundle_audit_markdown(&audit)), None)
        }
        AuditOutputFormat::Json => emit_artifact(&Artifact::Json(json!(audit)), None),
    }
}

fn run_audit_bundle_ci(args: AuditBundleArgs) -> Result<()> {
    let bundle_dir = args.bundle_dir()?.to_path_buf();
    match build_bundle_audit(&bundle_dir) {
        Ok(audit) => {
            if let Some(diagnostic) = bundle_audit_policy_failure(&audit, &args) {
                let failure = bundle_audit_policy_failure_receipt(&audit, &diagnostic);
                if let Some(out_dir) = args.out.as_deref() {
                    write_bundle_audit_receipts(&failure, out_dir)?;
                }
                emit_artifact(&Artifact::Json(json!(failure)), None)?;
                bail!(
                    "audit policy failed: {}: {}",
                    diagnostic.failure_class,
                    diagnostic.detail
                );
            }
            if let Some(out_dir) = args.out.as_deref() {
                write_bundle_audit_receipts(&audit, out_dir)?;
            }
            emit_artifact(&Artifact::Json(json!(audit)), None)
        }
        Err(err) => {
            let diagnostic = bundle_audit_failure_diagnostic(&err);
            let failure = bundle_audit_failure_receipt(&bundle_dir, &diagnostic);
            if let Some(out_dir) = args.out.as_deref() {
                write_bundle_audit_receipts(&failure, out_dir)?;
            }
            emit_artifact(&Artifact::Json(json!(failure)), None)?;
            bail!(
                "audit failed: {}: {}",
                diagnostic.failure_class,
                diagnostic.detail
            );
        }
    }
}

fn write_bundle_audit_receipts(audit: &BundleAudit, out_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create audit directory {}", out_dir.display()))?;
    let json_path = out_dir.join("bundle-audit.json");
    let md_path = out_dir.join("bundle-audit.md");
    fs::write(&json_path, serde_json::to_vec_pretty(audit)?)
        .with_context(|| format!("failed to write {}", json_path.display()))?;
    fs::write(&md_path, render_bundle_audit_markdown(audit))
        .with_context(|| format!("failed to write {}", md_path.display()))?;
    Ok((json_path, md_path))
}

fn run_export(args: ExportArgs) -> Result<()> {
    match args.target {
        ExportTarget::K8s(export) => run_export_k8s(export),
        ExportTarget::VaultKvJson(export) => run_export_vault_kv_json(export),
    }
}

fn run_export_k8s(args: ExportK8sArgs) -> Result<()> {
    let artifacts = load_bundle_export_artifacts(&args.bundle_dir)?;
    let payload = render_k8s_secret_yaml(&args.name, args.namespace.as_deref(), &artifacts);
    emit_artifact(&Artifact::Text(payload), args.out.as_deref())
}

fn run_export_vault_kv_json(args: ExportVaultKvJsonArgs) -> Result<()> {
    let artifacts = load_bundle_export_artifacts(&args.bundle_dir)?;
    let payload = render_vault_kv_json(&artifacts).context("failed to render Vault KV payload")?;
    emit_artifact(&Artifact::Text(payload), args.out.as_deref())
}

fn run_inspect(args: InspectArgs) -> Result<()> {
    let bytes = read_input(args.input.as_deref())?;
    let text = std::str::from_utf8(&bytes).ok();
    let detected = detect_kind(text.unwrap_or_default());
    let report = json!({
        "format": format!("{:?}", args.format).to_lowercase(),
        "size_bytes": bytes.len(),
        "line_count": text.map(|s| s.lines().count()).unwrap_or(0),
        "detected": detected,
    });
    emit_artifact(&Artifact::Json(report), args.out.as_deref())
}

fn run_materialize(args: MaterializeArgs) -> Result<()> {
    let manifest = load_materialize_manifest(&args.manifest)
        .with_context(|| format!("invalid materialize manifest {}", args.manifest.display()))?;
    let out_dir = args
        .out_dir
        .unwrap_or_else(|| PathBuf::from("target/uselesskey-fixtures"));
    let summary = materialize_manifest_to_dir(&manifest, &out_dir, args.check)
        .with_context(|| format!("failed to materialize {}", args.manifest.display()))?;

    if let Some(module_path) = args.emit_rs.as_deref() {
        emit_include_bytes_module(&manifest, &out_dir, module_path).with_context(|| {
            format!(
                "failed to emit include_bytes module {}",
                module_path.display()
            )
        })?;
    }

    let status = if args.check { "ok" } else { "written" };
    emit_artifact(
        &Artifact::Json(json!({
            "materialize": {
                "status": status,
                "out": out_dir,
                "count": summary.count,
                "files": summary.files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "check": args.check,
                "emit_rs": args.emit_rs,
            }
        })),
        None,
    )
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let manifest = load_materialize_manifest(&args.manifest)
        .with_context(|| format!("invalid materialize manifest {}", args.manifest.display()))?;
    let out_dir = args
        .out_dir
        .unwrap_or_else(|| PathBuf::from("target/uselesskey-fixtures"));
    let summary = materialize_manifest_to_dir(&manifest, &out_dir, true)
        .with_context(|| format!("failed to verify {}", args.manifest.display()))?;

    emit_artifact(
        &Artifact::Json(json!({
            "verify": {
                "status": "ok",
                "out": out_dir,
                "count": summary.count,
                "files": summary.files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            }
        })),
        None,
    )
}

fn load_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: BundleManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if manifest.version != 1 {
        bail!("unsupported bundle manifest version {}", manifest.version);
    }
    Ok(manifest)
}

fn verify_bundle_manifest(bundle_dir: &Path, manifest: &BundleManifest) -> Result<Vec<String>> {
    ensure_manifest_paths_safe(manifest)?;
    let format = parse_manifest_format(&manifest.format)?;
    let profile = parse_manifest_profile(&manifest.profile)?;
    let fx = Factory::deterministic_from_str(&manifest.seed);
    let mut expected_files = Vec::new();
    let mut expected_artifacts = Vec::new();

    for entry in bundle_entries(profile) {
        let bundle_format = entry.preferred_format(format, profile);
        let artifact =
            generate_bundle_entry_artifact(&fx, entry, &manifest.label, bundle_format, profile)
                .with_context(|| format!("failed to regenerate {}", entry.name()))?;
        let file_name = entry.file_name(bundle_format, &artifact);
        let expected = artifact_bytes(&artifact)?;
        let path = bundle_dir.join(&file_name);
        let actual =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        if actual != expected {
            bail!(
                "bundle verification failed: {} content mismatch",
                path.display()
            );
        }
        expected_artifacts.push(bundle_artifact_record(
            entry,
            bundle_format,
            &file_name,
            profile,
        ));
        expected_files.push(file_name);
    }
    let fixture_files = expected_files.clone();
    let mut expected_receipts = Vec::new();
    if !manifest.receipts.is_empty() {
        expected_receipts = bundle_receipt_records(profile);
        for receipt in &expected_receipts {
            let expected = artifact_bytes(&generate_bundle_receipt_artifact(
                &receipt.kind,
                &manifest.seed,
                &manifest.label,
                format,
                profile,
                &fixture_files,
                &expected_artifacts,
            )?)?;
            let path = bundle_dir.join(&receipt.path);
            let actual =
                fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
            if actual != expected {
                bail!(
                    "bundle verification failed: {} receipt mismatch",
                    path.display()
                );
            }
            expected_files.push(receipt.path.clone());
        }
    }

    if manifest.files != expected_files {
        bail!(
            "bundle verification failed: manifest file list mismatch; expected {:?}, found {:?}",
            expected_files,
            manifest.files
        );
    }

    if !manifest.artifacts.is_empty() && manifest.artifacts != expected_artifacts {
        bail!(
            "bundle verification failed: artifact metadata mismatch; expected {:?}, found {:?}",
            expected_artifacts,
            manifest.artifacts
        );
    }

    if !manifest.artifacts.is_empty() && manifest.receipts.is_empty() {
        bail!("bundle verification failed: receipt metadata missing");
    }

    if !manifest.receipts.is_empty() && manifest.receipts != expected_receipts {
        bail!(
            "bundle verification failed: receipt metadata mismatch; expected {:?}, found {:?}",
            expected_receipts,
            manifest.receipts
        );
    }

    Ok(expected_files)
}

fn render_bundle_inspection_summary(
    manifest: &BundleManifest,
    verified_file_count: usize,
) -> String {
    let profile_info = parse_manifest_profile(&manifest.profile)
        .ok()
        .map(profile_info);
    let artifact_count = if manifest.artifacts.is_empty() {
        verified_file_count
    } else {
        manifest.artifacts.len()
    };
    let scanner_safe = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .all(|artifact| artifact.scanner_safe),
        )
    };
    let runtime_material_count = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .filter(|artifact| !artifact.scanner_safe)
                .count(),
        )
    };
    let private_key_material = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .any(bundle_artifact_contains_private_key_material),
        )
    };
    let symmetric_secret_material = if manifest.artifacts.is_empty() {
        None
    } else {
        Some(
            manifest
                .artifacts
                .iter()
                .any(bundle_artifact_contains_symmetric_secret_material),
        )
    };
    let receipts = if manifest.receipts.is_empty() {
        "none".to_string()
    } else {
        manifest
            .receipts
            .iter()
            .map(|receipt| receipt.kind.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let files = if manifest.files.is_empty() {
        "none".to_string()
    } else {
        manifest
            .files
            .iter()
            .map(|file| format!("- {file}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let artifact_posture = if manifest.artifacts.is_empty() {
        "none".to_string()
    } else {
        manifest
            .artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "- {}: scanner_safe={}, kind={}, format={}, description={}",
                    artifact.path,
                    yes_no(artifact.scanner_safe),
                    artifact.kind,
                    artifact.format,
                    artifact.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let proof_path = profile_info
        .map(|info| info.proof_command)
        .unwrap_or("uselesskey verify-bundle <bundle-dir>");
    let boundary = profile_info
        .map(|info| info.not_proves.join("; "))
        .unwrap_or_else(|| "production security behavior".to_string());

    format!(
        concat!(
            "Bundle profile: {}\n",
            "Summary type: quick human bundle summary\n",
            "Purpose: {}\n",
            "Artifacts: {}\n",
            "Verified files: {}\n",
            "Scanner-safe: {}\n",
            "Private key material: {}\n",
            "Symmetric secret material: {}\n",
            "Runtime material artifacts: {}\n",
            "Verification: ok\n",
            "Receipts: {}\n",
            "Durable audit receipt: uselesskey audit-bundle <bundle-dir> --out <audit-dir>\n",
            "Proof/check path: {}\n",
            "Generated files:\n{}\n",
            "Artifact posture:\n{}\n",
            "Does not prove: {}\n",
        ),
        manifest.profile,
        profile_info.map_or("unknown profile", |info| info.purpose),
        artifact_count,
        verified_file_count,
        yes_no_unknown(scanner_safe),
        yes_no_unknown(private_key_material),
        yes_no_unknown(symmetric_secret_material),
        count_or_unknown(runtime_material_count),
        receipts,
        proof_path,
        files,
        artifact_posture,
        boundary
    )
}

fn build_bundle_audit(bundle_dir: &Path) -> Result<BundleAudit> {
    let manifest_path = bundle_dir.join("manifest.json");
    if !manifest_path.exists() {
        bail!("missing_manifest: {}", manifest_path.display());
    }
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid_manifest: {}", manifest_path.display()))?;
    ensure_manifest_paths_safe(&manifest)?;
    let profile = parse_manifest_profile(&manifest.profile)
        .map_err(|err| anyhow::anyhow!("unsupported_profile: {err}"))?;
    let info = profile_info(profile);

    let actual_files = collect_bundle_files(bundle_dir)?;
    let expected_files = expected_bundle_file_set(&manifest.files);
    let actual_file_set = actual_files.into_iter().collect::<BTreeSet<_>>();
    let missing_files = expected_files
        .difference(&actual_file_set)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected_files = actual_file_set
        .difference(&expected_files)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_files.is_empty() {
        bail!("missing_artifact: {}", missing_files.join(", "));
    }
    if !unexpected_files.is_empty() {
        bail!("unexpected_artifact: {}", unexpected_files.join(", "));
    }

    let receipt_kinds = manifest
        .receipts
        .iter()
        .map(|receipt| receipt.kind.clone())
        .collect::<BTreeSet<_>>();
    for required in bundle_receipt_records(profile)
        .iter()
        .map(|receipt| receipt.kind.as_str())
    {
        if !receipt_kinds.contains(required) {
            bail!("missing_receipt: {required}");
        }
    }
    validate_audit_surface_receipt(bundle_dir, &manifest)?;

    let files = verify_bundle_manifest(bundle_dir, &manifest)
        .with_context(|| format!("profile_validation_failed: {}", bundle_dir.display()))?;

    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| BundleAuditArtifact {
            path: artifact.path.clone(),
            kind: artifact.kind.clone(),
            format: artifact.format.clone(),
            scanner_safe: artifact.scanner_safe,
            runtime_material: !artifact.scanner_safe,
            description: artifact.description.clone(),
        })
        .collect::<Vec<_>>();
    let scanner_safe_count = artifacts
        .iter()
        .filter(|artifact| artifact.scanner_safe)
        .count();
    let runtime_material_count = artifacts.len() - scanner_safe_count;

    Ok(BundleAudit {
        version: 1,
        status: "pass".to_string(),
        bundle_path: display_path(bundle_dir),
        profile: manifest.profile.clone(),
        manifest_version: manifest.version,
        manifest_path: "manifest.json".to_string(),
        artifact_count: artifacts.len(),
        receipt_count: manifest.receipts.len(),
        scanner_safe_count,
        runtime_material_count,
        files,
        artifacts,
        receipts: manifest.receipts.clone(),
        missing_files,
        unexpected_files,
        checks: vec![
            BundleAuditCheck::pass("manifest", "invalid_manifest", "manifest parsed"),
            BundleAuditCheck::pass(
                "path-containment",
                "path_escape",
                "manifest paths are safe relative paths contained by the bundle",
            ),
            BundleAuditCheck::pass(
                "artifact-content",
                "missing_artifact",
                "manifest artifacts regenerate and verify",
            ),
            BundleAuditCheck::pass(
                "receipts",
                "missing_receipt",
                "bundle product receipts are present",
            ),
            BundleAuditCheck::pass(
                "scanner-safe-classification",
                "scanner_safe_mismatch",
                "audit-surface receipt matches manifest scanner-safe counts",
            ),
            BundleAuditCheck::pass(
                "runtime-material-classification",
                "runtime_material_mismatch",
                "audit-surface receipt matches manifest runtime-material counts",
            ),
            BundleAuditCheck::pass(
                "profile-validation",
                "profile_validation_failed",
                "profile-specific generated files match the manifest",
            ),
        ],
        boundaries: bundle_audit_boundaries(&info),
        does_not_prove: info
            .not_proves
            .iter()
            .map(|boundary| (*boundary).to_string())
            .collect(),
    })
}

fn render_bundle_audit_markdown(audit: &BundleAudit) -> String {
    let mut out = String::new();
    out.push_str("# uselesskey Bundle Audit\n\n");
    out.push_str(&format!("- Status: {}\n", markdown_inline(&audit.status)));
    out.push_str(&format!(
        "- Bundle: {}\n",
        markdown_inline(&audit.bundle_path)
    ));
    out.push_str(&format!("- Profile: {}\n", markdown_inline(&audit.profile)));
    out.push_str("- Receipt type: durable metadata-only reviewer/CI receipt\n");
    out.push_str("- Quick summary: uselesskey inspect-bundle <bundle-dir>\n");
    out.push_str(
        "- Payload posture: raw generated fixture payloads are not copied into this receipt\n",
    );
    out.push_str(&format!(
        "- Manifest: {} (version {})\n",
        markdown_inline(&audit.manifest_path),
        audit.manifest_version
    ));
    out.push_str(&format!("- Artifacts: {}\n", audit.artifact_count));
    out.push_str(&format!("- Receipts: {}\n", audit.receipt_count));
    out.push_str(&format!(
        "- Scanner-safe artifacts: {}\n",
        audit.scanner_safe_count
    ));
    out.push_str(&format!(
        "- Runtime material artifacts: {}\n\n",
        audit.runtime_material_count
    ));

    out.push_str("## Checks\n\n");
    out.push_str("| Check | Status | Failure class | Detail |\n");
    out.push_str("|---|---|---|---|\n");
    for check in &audit.checks {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            markdown_table_cell(&check.name),
            markdown_table_cell(&check.status),
            markdown_table_cell(&check.failure_class),
            markdown_table_cell(&check.detail)
        ));
    }

    out.push_str("\n## Artifacts\n\n");
    out.push_str("| Path | Kind | Format | Scanner-safe | Runtime material |\n");
    out.push_str("|---|---|---|---|---|\n");
    for artifact in &audit.artifacts {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            markdown_table_cell(&artifact.path),
            markdown_table_cell(&artifact.kind),
            markdown_table_cell(&artifact.format),
            yes_no(artifact.scanner_safe),
            yes_no(artifact.runtime_material)
        ));
    }

    out.push_str("\n## Receipts\n\n");
    for receipt in &audit.receipts {
        out.push_str(&format!(
            "- {}: {}\n",
            markdown_inline(&receipt.kind),
            markdown_inline(&receipt.path)
        ));
    }

    out.push_str("\n## Boundaries\n\n");
    for boundary in &audit.boundaries {
        out.push_str(&format!("- {}\n", markdown_inline(boundary)));
    }

    out.push_str("\n## Does Not Prove\n\n");
    for boundary in &audit.does_not_prove {
        out.push_str(&format!("- {}\n", markdown_inline(boundary)));
    }

    out
}

fn markdown_inline(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\r' | '\n' => escaped.push(' '),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn markdown_table_cell(value: &str) -> String {
    markdown_inline(value).replace('|', r"\|")
}

fn render_bundle_audit_summary(audit: &BundleAudit, out_dir: Option<&Path>) -> String {
    let receipts = if audit.receipt_count == 0 {
        "none"
    } else {
        "present"
    };
    let mut out = format!(
        concat!(
            "Bundle audit: {}\n",
            "Profile: {}\n",
            "Artifacts: {}\n",
            "Scanner-safe: {}\n",
            "Runtime material: {}\n",
            "Receipts: {}\n",
            "Boundaries: local consistency only\n",
        ),
        audit.status,
        audit.profile,
        audit.artifact_count,
        audit.scanner_safe_count,
        audit.runtime_material_count,
        receipts
    );
    if let Some(out_dir) = out_dir {
        out.push_str(&format!("Audit receipts: {}\n", display_path(out_dir)));
    }
    out
}

fn ensure_manifest_paths_safe(manifest: &BundleManifest) -> Result<()> {
    for path in manifest
        .files
        .iter()
        .chain(manifest.artifacts.iter().map(|artifact| &artifact.path))
        .chain(manifest.receipts.iter().map(|receipt| &receipt.path))
    {
        if !is_safe_bundle_relative_path(path) {
            bail!("path_escape: {}", bundle_manifest_path_context(path));
        }
    }
    Ok(())
}

fn is_safe_bundle_relative_path(path: &str) -> bool {
    if path.is_empty() || path.chars().any(|ch| ch.is_control()) {
        return false;
    }
    if has_windows_absolute_or_drive_prefix(path) {
        return false;
    }
    if path.split(['/', '\\']).any(str::is_empty) {
        return false;
    }

    let path = Path::new(path);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn has_windows_absolute_or_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with('\\')
        || bytes
            .get(..2)
            .is_some_and(|prefix| prefix[0].is_ascii_alphabetic() && prefix[1] == b':')
}

fn bundle_manifest_path_context(path: &str) -> String {
    if path.is_empty() {
        "<empty>".to_string()
    } else {
        path.escape_default().to_string()
    }
}

fn collect_bundle_files(bundle_dir: &Path) -> Result<Vec<String>> {
    let mut stack = vec![bundle_dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                let relative = path.strip_prefix(bundle_dir).with_context(|| {
                    format!("failed to make {} relative to bundle", path.display())
                })?;
                files.push(display_path(relative));
            }
        }
    }
    files.sort();
    Ok(files)
}

fn expected_bundle_file_set(files: &[String]) -> BTreeSet<String> {
    files
        .iter()
        .cloned()
        .chain(std::iter::once("manifest.json".to_string()))
        .collect()
}

fn validate_audit_surface_receipt(bundle_dir: &Path, manifest: &BundleManifest) -> Result<()> {
    let receipt_path = bundle_dir.join("receipts/audit-surface.json");
    let raw = fs::read_to_string(&receipt_path)
        .with_context(|| format!("missing_receipt: {}", receipt_path.display()))?;
    let receipt: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| "invalid_receipt: audit-surface")?;
    let scanner_safe_count = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.scanner_safe)
        .count();
    let runtime_material_count = manifest.artifacts.len() - scanner_safe_count;
    let scanner_safe_all = scanner_safe_count == manifest.artifacts.len();

    let checks = [
        (
            "profile",
            "scanner_safe_mismatch",
            receipt.get("profile").and_then(serde_json::Value::as_str)
                == Some(manifest.profile.as_str()),
        ),
        (
            "artifact_count",
            "scanner_safe_mismatch",
            receipt
                .get("artifact_count")
                .and_then(serde_json::Value::as_u64)
                == Some(manifest.artifacts.len() as u64),
        ),
        (
            "scanner_safe_count",
            "scanner_safe_mismatch",
            receipt
                .get("scanner_safe_count")
                .and_then(serde_json::Value::as_u64)
                == Some(scanner_safe_count as u64),
        ),
        (
            "runtime_material_count",
            "runtime_material_mismatch",
            receipt
                .get("runtime_material_count")
                .and_then(serde_json::Value::as_u64)
                == Some(runtime_material_count as u64),
        ),
        (
            "scanner_safe",
            "scanner_safe_mismatch",
            receipt
                .get("scanner_safe")
                .and_then(serde_json::Value::as_bool)
                == Some(scanner_safe_all),
        ),
    ];
    for (field, failure_class, matches) in checks {
        if !matches {
            bail!("{failure_class}: audit-surface field `{field}`");
        }
    }
    Ok(())
}

const BUNDLE_AUDIT_LOCAL_BOUNDARY: &str =
    "audit-bundle proves local bundle consistency and metadata classification";
const BUNDLE_AUDIT_REPO_CLAIM_BOUNDARY: &str = "audit-bundle is not standalone proof for broader repo public claims; use cargo xtask claim-proof from a repo checkout";
const BUNDLE_AUDIT_RELEASE_BOUNDARY: &str =
    "audit-bundle does not prove release readiness; use release-evidence for release proof";
const BUNDLE_AUDIT_METADATA_ONLY_BOUNDARY: &str =
    "audit receipts contain metadata only and do not copy generated fixture payloads";

fn bundle_audit_boundaries(info: &ProfileInfo) -> Vec<String> {
    vec![
        BUNDLE_AUDIT_LOCAL_BOUNDARY.to_string(),
        BUNDLE_AUDIT_REPO_CLAIM_BOUNDARY.to_string(),
        BUNDLE_AUDIT_RELEASE_BOUNDARY.to_string(),
        format!("profile proof/check path: {}", info.proof_command),
        BUNDLE_AUDIT_METADATA_ONLY_BOUNDARY.to_string(),
    ]
}

fn build_doctor_report() -> DoctorReport {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let current_dir_result = env::current_dir();
    let current_dir = current_dir_result
        .as_ref()
        .map(|path| display_path(path))
        .unwrap_or_else(|_| "unknown".to_string());
    let known_profiles = DISCOVERABLE_PROFILES
        .iter()
        .map(|profile| profile.manifest_name().to_string())
        .collect::<Vec<_>>();

    let mut checks = Vec::new();
    checks.push(DoctorCheck::pass(
        "cli-version",
        format!("uselesskey-cli {version}"),
    ));

    match &current_dir_result {
        Ok(path) => checks.push(DoctorCheck::pass(
            "current-directory",
            format!("current directory is {}", display_path(path)),
        )),
        Err(err) => checks.push(DoctorCheck::fail(
            "current-directory",
            format!("failed to read current directory: {err}"),
        )),
    }

    checks.push(target_write_access_check(
        current_dir_result.as_deref().ok(),
    ));
    checks.push(output_path_safety_check());

    if serde_json::to_string(&json!({"doctor": "ok"})).is_ok() {
        checks.push(DoctorCheck::pass(
            "json-output",
            "JSON output support is available",
        ));
    } else {
        checks.push(DoctorCheck::fail(
            "json-output",
            "failed to serialize a JSON doctor probe",
        ));
    }

    if known_profiles.is_empty() {
        checks.push(DoctorCheck::fail(
            "known-profiles",
            "no installed bundle profiles are discoverable",
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "known-profiles",
            format!("known profiles: {}", known_profiles.join(", ")),
        ));
    }

    let status = if checks.iter().all(|check| check.status == "pass") {
        "pass"
    } else {
        "fail"
    }
    .to_string();

    DoctorReport {
        version: 1,
        status,
        cli_version: version,
        current_dir,
        known_profiles,
        checks,
        next_steps: vec![
            "uselesskey profiles".to_string(),
            "uselesskey bundle --profile webhook --out target/uselesskey-webhook".to_string(),
            "uselesskey audit-bundle target/uselesskey-webhook --ci --out target/uselesskey-webhook-audit".to_string(),
        ],
        boundaries: vec![
            "doctor checks installed CLI concerns only".to_string(),
            "public claim proof and release proof remain repo-local workflows".to_string(),
            "doctor does not inspect or copy generated fixture payloads".to_string(),
        ],
    }
}

fn target_write_access_check(current_dir: Option<&Path>) -> DoctorCheck {
    let Some(current_dir) = current_dir else {
        return DoctorCheck::fail(
            "target-write-access",
            "current directory is unavailable, so target write access was not checked",
        );
    };
    let probe_dir = current_dir.join("target/uselesskey-doctor");
    let probe_path = probe_dir.join(".write-probe");
    let result = fs::create_dir_all(&probe_dir)
        .and_then(|()| fs::write(&probe_path, b"ok"))
        .and_then(|()| fs::remove_file(&probe_path));

    match result {
        Ok(()) => {
            let _ = fs::remove_dir(&probe_dir);
            DoctorCheck::pass(
                "target-write-access",
                format!(
                    "can write under {}",
                    display_path(&current_dir.join("target"))
                ),
            )
        }
        Err(err) => DoctorCheck::fail(
            "target-write-access",
            format!(
                "failed to write under {}: {err}",
                display_path(&current_dir.join("target"))
            ),
        ),
    }
}

fn output_path_safety_check() -> DoctorCheck {
    let unsafe_hints = DISCOVERABLE_PROFILES
        .iter()
        .map(|profile| profile.output_dir_hint())
        .filter(|hint| !is_safe_default_output_hint(hint))
        .collect::<Vec<_>>();

    if unsafe_hints.is_empty() {
        DoctorCheck::pass(
            "output-path-safety",
            "default profile output paths are relative target/ paths",
        )
    } else {
        DoctorCheck::fail(
            "output-path-safety",
            format!(
                "unsafe default profile output paths: {}",
                unsafe_hints.join(", ")
            ),
        )
    }
}

fn is_safe_default_output_hint(hint: &str) -> bool {
    is_safe_bundle_relative_path(hint) && hint.starts_with("target/")
}

fn render_doctor_report(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str("uselesskey doctor\n");
    out.push_str(&format!("Status: {}\n", report.status));
    out.push_str(&format!("CLI version: {}\n", report.cli_version));
    out.push_str(&format!("Current directory: {}\n", report.current_dir));
    out.push_str(&format!(
        "Known profiles: {}\n",
        report.known_profiles.join(", ")
    ));
    out.push_str("\nChecks:\n");
    for check in &report.checks {
        out.push_str(&format!(
            "- {}: {} - {}\n",
            check.name, check.status, check.detail
        ));
    }
    out.push_str("\nNext steps:\n");
    for step in &report.next_steps {
        out.push_str(&format!("- {step}\n"));
    }
    out.push_str("\nBoundaries:\n");
    for boundary in &report.boundaries {
        out.push_str(&format!("- {boundary}\n"));
    }
    out
}

const BUNDLE_AUDIT_FAILURE_CLASSES: [&str; 11] = [
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
];

fn bundle_audit_failure_receipt(
    bundle_dir: &Path,
    diagnostic: &BundleAuditFailureDiagnostic,
) -> BundleAudit {
    BundleAudit {
        version: 1,
        status: "fail".to_string(),
        bundle_path: display_path(bundle_dir),
        profile: "unknown".to_string(),
        manifest_version: 0,
        manifest_path: "manifest.json".to_string(),
        artifact_count: 0,
        receipt_count: 0,
        scanner_safe_count: 0,
        runtime_material_count: 0,
        files: vec![],
        artifacts: vec![],
        receipts: vec![],
        missing_files: vec![],
        unexpected_files: vec![],
        checks: vec![BundleAuditCheck::fail(
            "bundle-audit",
            diagnostic.failure_class,
            &diagnostic.detail,
        )],
        boundaries: vec![
            BUNDLE_AUDIT_LOCAL_BOUNDARY.to_string(),
            BUNDLE_AUDIT_REPO_CLAIM_BOUNDARY.to_string(),
            BUNDLE_AUDIT_RELEASE_BOUNDARY.to_string(),
            BUNDLE_AUDIT_METADATA_ONLY_BOUNDARY.to_string(),
        ],
        does_not_prove: vec![
            "broader repo public claims by itself".to_string(),
            "release readiness".to_string(),
            "provider compatibility".to_string(),
            "production security".to_string(),
            "scanner evasion".to_string(),
            "downstream verifier correctness".to_string(),
        ],
    }
}

fn bundle_audit_policy_failure_receipt(
    audit: &BundleAudit,
    diagnostic: &BundleAuditFailureDiagnostic,
) -> BundleAudit {
    BundleAudit {
        version: audit.version,
        status: "fail".to_string(),
        bundle_path: audit.bundle_path.clone(),
        profile: audit.profile.clone(),
        manifest_version: audit.manifest_version,
        manifest_path: audit.manifest_path.clone(),
        artifact_count: audit.artifact_count,
        receipt_count: audit.receipt_count,
        scanner_safe_count: audit.scanner_safe_count,
        runtime_material_count: audit.runtime_material_count,
        files: audit.files.clone(),
        artifacts: audit.artifacts.clone(),
        receipts: audit.receipts.clone(),
        missing_files: audit.missing_files.clone(),
        unexpected_files: audit.unexpected_files.clone(),
        checks: vec![BundleAuditCheck::fail(
            "bundle-audit-policy",
            diagnostic.failure_class,
            &diagnostic.detail,
        )],
        boundaries: audit.boundaries.clone(),
        does_not_prove: audit.does_not_prove.clone(),
    }
}

fn bundle_audit_policy_failure(
    audit: &BundleAudit,
    args: &AuditBundleArgs,
) -> Option<BundleAuditFailureDiagnostic> {
    if let Some(expected) = args.expect_profile.as_deref()
        && audit.profile != expected
    {
        return Some(BundleAuditFailureDiagnostic {
            failure_class: "profile_validation_failed",
            detail: format!(
                "expected profile `{expected}`, found `{}`. Fix: audit the matching bundle or update --expect-profile for this CI job.",
                audit.profile
            ),
        });
    }

    if args.policy == Some(AuditPolicy::Strict) {
        if audit.status != "pass" {
            return Some(BundleAuditFailureDiagnostic {
                failure_class: "profile_validation_failed",
                detail: format!(
                    "strict policy requires audit status `pass`, found `{}`. Fix: regenerate and audit the bundle.",
                    audit.status
                ),
            });
        }
        if let Some(check) = audit.checks.iter().find(|check| check.status != "pass") {
            return Some(BundleAuditFailureDiagnostic {
                failure_class: "profile_validation_failed",
                detail: format!(
                    "strict policy requires all checks to pass; `{}` was `{}`. Fix: regenerate and audit the bundle.",
                    check.name, check.status
                ),
            });
        }
        if !audit.missing_files.is_empty() {
            return Some(BundleAuditFailureDiagnostic {
                failure_class: "missing_artifact",
                detail: format!(
                    "strict policy found missing bundle files: {}. Fix: regenerate the bundle.",
                    audit.missing_files.join(", ")
                ),
            });
        }
        if !audit.unexpected_files.is_empty() {
            return Some(BundleAuditFailureDiagnostic {
                failure_class: "unexpected_artifact",
                detail: format!(
                    "strict policy found unexpected bundle files: {}. Fix: remove extra files or regenerate into an empty target directory.",
                    audit.unexpected_files.join(", ")
                ),
            });
        }
    }

    None
}

fn bundle_audit_failure_class(err: &anyhow::Error) -> &'static str {
    for source in err.chain() {
        let message = source.to_string();
        for failure_class in BUNDLE_AUDIT_FAILURE_CLASSES {
            if message == failure_class || message.starts_with(&format!("{failure_class}:")) {
                return failure_class;
            }
        }
    }
    "profile_validation_failed"
}

struct BundleAuditFailureDiagnostic {
    failure_class: &'static str,
    detail: String,
}

fn bundle_audit_failure_diagnostic(err: &anyhow::Error) -> BundleAuditFailureDiagnostic {
    let failure_class = bundle_audit_failure_class(err);
    let context = bundle_audit_failure_context(err, failure_class);
    let detail = match failure_class {
        "missing_manifest" => {
            "manifest.json is missing from the bundle root. Fix: regenerate the bundle or pass the directory created by `uselesskey bundle --out`.".to_string()
        }
        "invalid_manifest" => format_with_context(
            "manifest.json could not be parsed or has an unsupported manifest version",
            context.as_deref(),
            "regenerate the bundle with the same uselesskey version or inspect manifest.json for corruption",
        ),
        "path_escape" => format_with_context(
            "manifest.json lists an unsafe bundle path",
            context.as_deref(),
            "regenerate the bundle or inspect the manifest producer; bundle paths must be safe relative paths contained by the bundle",
        ),
        "missing_artifact" => format_with_context(
            "manifest.json lists files that are absent from the bundle",
            context.as_deref(),
            "regenerate the bundle or restore the missing generated files",
        ),
        "unexpected_artifact" => format_with_context(
            "the bundle contains files that are not listed in manifest.json",
            context.as_deref(),
            "remove extra files or regenerate into an empty target directory",
        ),
        "missing_receipt" => format_with_context(
            "a required bundle receipt is missing",
            context.as_deref(),
            "regenerate the bundle with a current uselesskey CLI",
        ),
        "invalid_receipt" => format_with_context(
            "a bundle receipt could not be parsed or did not match the expected JSON shape",
            context.as_deref(),
            "regenerate the bundle; if the bundle was persisted, inspect receipt corruption",
        ),
        "scanner_safe_mismatch" => format_with_context(
            "audit-surface scanner-safe metadata differs from manifest artifact metadata",
            context.as_deref(),
            "regenerate the bundle with the same uselesskey version",
        ),
        "runtime_material_mismatch" => format_with_context(
            "audit-surface runtime-material metadata differs from manifest artifact metadata",
            context.as_deref(),
            "regenerate the bundle with the same uselesskey version",
        ),
        "unsupported_profile" => format_with_context(
            "manifest.json names a profile this uselesskey CLI cannot audit",
            context.as_deref(),
            "upgrade uselesskey or audit with the CLI version that generated the bundle",
        ),
        _ => format_with_context(
            "profile-specific generated files do not match manifest metadata",
            context.as_deref(),
            "regenerate the bundle with the same uselesskey version",
        ),
    };

    BundleAuditFailureDiagnostic {
        failure_class,
        detail,
    }
}

fn bundle_audit_failure_context(err: &anyhow::Error, failure_class: &str) -> Option<String> {
    let prefix = format!("{failure_class}:");
    err.chain().find_map(|source| {
        let message = source.to_string();
        message
            .strip_prefix(&prefix)
            .map(str::trim)
            .filter(|detail| !detail.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn format_with_context(summary: &str, context: Option<&str>, fix: &str) -> String {
    match context {
        Some(context) => format!("{summary}. Detail: {context}. Fix: {fix}."),
        None => format!("{summary}. Fix: {fix}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_audit_failure_diagnostics_are_class_specific() {
        let cases = [
            (
                "missing_manifest",
                "manifest.json is missing from the bundle root",
                "pass the directory created by `uselesskey bundle --out`",
                false,
            ),
            (
                "invalid_manifest",
                "manifest.json could not be parsed or has an unsupported manifest version",
                "inspect manifest.json for corruption",
                true,
            ),
            (
                "path_escape",
                "manifest.json lists an unsafe bundle path",
                "bundle paths must be safe relative paths contained by the bundle",
                true,
            ),
            (
                "missing_artifact",
                "manifest.json lists files that are absent from the bundle",
                "restore the missing generated files",
                true,
            ),
            (
                "unexpected_artifact",
                "the bundle contains files that are not listed in manifest.json",
                "regenerate into an empty target directory",
                true,
            ),
            (
                "missing_receipt",
                "a required bundle receipt is missing",
                "regenerate the bundle with a current uselesskey CLI",
                true,
            ),
            (
                "invalid_receipt",
                "a bundle receipt could not be parsed or did not match the expected JSON shape",
                "inspect receipt corruption",
                true,
            ),
            (
                "scanner_safe_mismatch",
                "audit-surface scanner-safe metadata differs from manifest artifact metadata",
                "regenerate the bundle with the same uselesskey version",
                true,
            ),
            (
                "runtime_material_mismatch",
                "audit-surface runtime-material metadata differs from manifest artifact metadata",
                "regenerate the bundle with the same uselesskey version",
                true,
            ),
            (
                "unsupported_profile",
                "manifest.json names a profile this uselesskey CLI cannot audit",
                "audit with the CLI version that generated the bundle",
                true,
            ),
            (
                "profile_validation_failed",
                "profile-specific generated files do not match manifest metadata",
                "regenerate the bundle with the same uselesskey version",
                true,
            ),
        ];

        for (failure_class, summary, fix, includes_context) in cases {
            let err = anyhow::anyhow!("{failure_class}: sample-context");
            let diagnostic = bundle_audit_failure_diagnostic(&err);
            assert_eq!(diagnostic.failure_class, failure_class);
            assert!(
                diagnostic.detail.contains(summary),
                "{failure_class} detail did not contain summary: {}",
                diagnostic.detail
            );
            assert!(
                diagnostic.detail.contains(fix),
                "{failure_class} detail did not contain fix: {}",
                diagnostic.detail
            );
            assert_eq!(
                diagnostic.detail.contains("Detail: sample-context"),
                includes_context,
                "{failure_class} context inclusion changed: {}",
                diagnostic.detail
            );
        }
    }

    fn audit_bundle_policy_test_args(
        expect_profile: Option<&str>,
        policy: Option<AuditPolicy>,
    ) -> AuditBundleArgs {
        AuditBundleArgs {
            bundle_dir: Some(PathBuf::from("target/uselesskey-webhook")),
            path: None,
            out: None,
            format: AuditOutputFormat::Markdown,
            ci: true,
            expect_profile: expect_profile.map(str::to_string),
            policy,
            summary: false,
        }
    }

    fn audit_bundle_policy_test_audit() -> BundleAudit {
        BundleAudit {
            version: 1,
            status: "pass".to_string(),
            bundle_path: "target/uselesskey-webhook".to_string(),
            profile: "webhook".to_string(),
            manifest_version: 1,
            manifest_path: "manifest.json".to_string(),
            artifact_count: 1,
            receipt_count: 1,
            scanner_safe_count: 0,
            runtime_material_count: 1,
            files: vec!["manifest.json".to_string()],
            artifacts: vec![],
            receipts: vec![],
            missing_files: vec![],
            unexpected_files: vec![],
            checks: vec![BundleAuditCheck::pass(
                "manifest",
                "invalid_manifest",
                "manifest parsed",
            )],
            boundaries: vec!["audit-bundle proves local bundle consistency only".to_string()],
            does_not_prove: vec!["production security".to_string()],
        }
    }

    #[test]
    fn bundle_audit_markdown_escapes_bundle_metadata() {
        let audit = BundleAudit {
            version: 1,
            status: "pass".to_string(),
            bundle_path: "target/uselesskey-webhook<script>alert(1)</script>\n## forged-heading"
                .to_string(),
            profile: "webhook".to_string(),
            manifest_version: 1,
            manifest_path: "manifest.json".to_string(),
            artifact_count: 1,
            receipt_count: 1,
            scanner_safe_count: 0,
            runtime_material_count: 1,
            files: vec![],
            artifacts: vec![BundleAuditArtifact {
                path: "requests/<valid>|request.json".to_string(),
                kind: "webhook|request".to_string(),
                format: "json|manifest".to_string(),
                scanner_safe: false,
                runtime_material: true,
                description: "runtime webhook request".to_string(),
            }],
            receipts: vec![BundleReceiptRecord {
                path: "receipts/audit-surface.json<img src=x onerror=alert(1)>\n- forged receipt"
                    .to_string(),
                kind: "audit|surface".to_string(),
                profile: "webhook".to_string(),
                description: "audit surface".to_string(),
            }],
            missing_files: vec![],
            unexpected_files: vec![],
            checks: vec![BundleAuditCheck::pass(
                "profile|validation",
                "profile_validation_failed",
                "detail|with <b>html</b> & table separator\nand forged row",
            )],
            boundaries: vec!["audit receipts contain metadata only\nand stay local".to_string()],
            does_not_prove: vec!["production security\nor provider compatibility".to_string()],
        };

        let markdown = render_bundle_audit_markdown(&audit);

        assert!(markdown.contains(
            "- Bundle: target/uselesskey-webhook&lt;script&gt;alert(1)&lt;/script&gt; ## forged-heading"
        ));
        assert!(!markdown.contains("\n## forged-heading"));
        assert!(markdown.contains(
            "| profile\\|validation | pass | profile_validation_failed | detail\\|with &lt;b&gt;html&lt;/b&gt; &amp; table separator and forged row |"
        ));
        assert!(markdown.contains(
            "| requests/&lt;valid&gt;\\|request.json | webhook\\|request | json\\|manifest | no | yes |"
        ));
        assert!(markdown.contains(
            "- audit|surface: receipts/audit-surface.json&lt;img src=x onerror=alert(1)&gt; - forged receipt"
        ));
        assert!(!markdown.contains("\n- forged receipt"));
        assert!(!markdown.contains("<script>"));
        assert!(!markdown.contains("<img"));
        assert!(!markdown.contains("<b>html</b>"));
        assert!(markdown.contains("- audit receipts contain metadata only and stay local"));
        assert!(markdown.contains("- production security or provider compatibility"));
    }

    #[test]
    fn audit_bundle_policy_accepts_matching_profile_and_strict_pass() {
        let audit = audit_bundle_policy_test_audit();
        let args = audit_bundle_policy_test_args(Some("webhook"), Some(AuditPolicy::Strict));

        assert!(bundle_audit_policy_failure(&audit, &args).is_none());
    }

    #[test]
    fn audit_bundle_policy_rejects_expected_profile_mismatch() -> Result<()> {
        let audit = audit_bundle_policy_test_audit();
        let args = audit_bundle_policy_test_args(Some("tls"), Some(AuditPolicy::Strict));
        let diagnostic = bundle_audit_policy_failure(&audit, &args)
            .ok_or_else(|| anyhow::anyhow!("expected profile mismatch failure"))?;

        assert_eq!(diagnostic.failure_class, "profile_validation_failed");
        assert!(diagnostic.detail.contains("expected profile `tls`"));
        Ok(())
    }

    #[test]
    fn audit_bundle_policy_strict_rejects_non_pass_status() -> Result<()> {
        let mut audit = audit_bundle_policy_test_audit();
        audit.status = "fail".to_string();
        let args = audit_bundle_policy_test_args(None, Some(AuditPolicy::Strict));
        let diagnostic = bundle_audit_policy_failure(&audit, &args)
            .ok_or_else(|| anyhow::anyhow!("expected strict status failure"))?;

        assert_eq!(diagnostic.failure_class, "profile_validation_failed");
        assert!(diagnostic.detail.contains("requires audit status `pass`"));
        Ok(())
    }

    #[test]
    fn audit_bundle_policy_strict_rejects_non_pass_check() -> Result<()> {
        let mut audit = audit_bundle_policy_test_audit();
        audit.checks[0].status = "fail".to_string();
        let args = audit_bundle_policy_test_args(None, Some(AuditPolicy::Strict));
        let diagnostic = bundle_audit_policy_failure(&audit, &args)
            .ok_or_else(|| anyhow::anyhow!("expected strict check failure"))?;

        assert_eq!(diagnostic.failure_class, "profile_validation_failed");
        assert!(diagnostic.detail.contains("requires all checks to pass"));
        Ok(())
    }

    #[test]
    fn audit_bundle_policy_strict_rejects_missing_files() -> Result<()> {
        let mut audit = audit_bundle_policy_test_audit();
        audit.missing_files.push("manifest.json".to_string());
        let args = audit_bundle_policy_test_args(None, Some(AuditPolicy::Strict));
        let diagnostic = bundle_audit_policy_failure(&audit, &args)
            .ok_or_else(|| anyhow::anyhow!("expected strict missing-files failure"))?;

        assert_eq!(diagnostic.failure_class, "missing_artifact");
        assert!(diagnostic.detail.contains("missing bundle files"));
        Ok(())
    }

    #[test]
    fn audit_bundle_policy_strict_rejects_unexpected_files() -> Result<()> {
        let mut audit = audit_bundle_policy_test_audit();
        audit.unexpected_files.push("extra.json".to_string());
        let args = audit_bundle_policy_test_args(None, Some(AuditPolicy::Strict));
        let diagnostic = bundle_audit_policy_failure(&audit, &args)
            .ok_or_else(|| anyhow::anyhow!("expected strict unexpected-files failure"))?;

        assert_eq!(diagnostic.failure_class, "unexpected_artifact");
        assert!(diagnostic.detail.contains("unexpected bundle files"));
        Ok(())
    }

    #[test]
    fn default_output_hint_safety_requires_relative_target_paths() {
        assert!(is_safe_default_output_hint("target/uselesskey-webhook"));
        assert!(!is_safe_default_output_hint("fixtures/uselesskey-webhook"));
        assert!(!is_safe_default_output_hint("target/../escape"));
        assert!(!is_safe_default_output_hint("../target/uselesskey-webhook"));
    }

    #[test]
    fn bundle_relative_path_safety_rejects_control_characters() {
        assert!(is_safe_bundle_relative_path("receipts/audit-surface.json"));
        assert!(!is_safe_bundle_relative_path(""));
        assert!(!is_safe_bundle_relative_path(
            "receipts/audit-surface\n.json"
        ));
        assert!(!is_safe_bundle_relative_path(
            "receipts/audit-surface\r.json"
        ));
        assert!(!is_safe_bundle_relative_path(
            "receipts/audit-surface\t.json"
        ));
    }

    #[test]
    fn bundle_relative_path_safety_rejects_absolute_and_parent_paths() {
        assert!(is_safe_bundle_relative_path("receipts/audit-surface.json"));
        assert!(is_safe_bundle_relative_path(
            "./receipts/audit-surface.json"
        ));
        assert!(!is_safe_bundle_relative_path("../escape.json"));
        assert!(!is_safe_bundle_relative_path("receipts/../escape.json"));
        assert!(!is_safe_bundle_relative_path("/tmp/secret.pem"));
        assert!(!is_safe_bundle_relative_path(r"\secret.pem"));
        assert!(!is_safe_bundle_relative_path(r"\\server\share\secret.pem"));
    }

    #[test]
    fn bundle_relative_path_safety_rejects_empty_components() {
        assert!(!is_safe_bundle_relative_path(
            "receipts//audit-surface.json"
        ));
        assert!(!is_safe_bundle_relative_path(
            "receipts/audit-surface.json/"
        ));
        assert!(!is_safe_bundle_relative_path(r"receipts\"));
        assert!(!is_safe_bundle_relative_path(
            r"receipts\\audit-surface.json"
        ));
    }

    #[test]
    fn bundle_relative_path_safety_rejects_windows_drive_prefixes() {
        assert!(!is_safe_bundle_relative_path(r"C:\secret.pem"));
        assert!(!is_safe_bundle_relative_path("C:/secret.pem"));
        assert!(!is_safe_bundle_relative_path("C:secret.pem"));
    }

    #[test]
    fn bundle_manifest_path_context_is_display_safe() {
        assert_eq!(bundle_manifest_path_context(""), "<empty>");
        assert_eq!(
            bundle_manifest_path_context("receipts/audit-surface\n.json"),
            "receipts/audit-surface\\n.json"
        );
        assert_eq!(
            bundle_manifest_path_context("receipts/audit-surface\r.json"),
            "receipts/audit-surface\\r.json"
        );
        assert_eq!(
            bundle_manifest_path_context("receipts/audit-surface\t.json"),
            "receipts/audit-surface\\t.json"
        );
    }

    #[test]
    fn helper_formatters_cover_all_branches() {
        assert_eq!(yes_no_unknown(Some(true)), "yes");
        assert_eq!(yes_no_unknown(Some(false)), "no");
        assert_eq!(yes_no_unknown(None), "unknown");

        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");

        assert_eq!(count_or_unknown(Some(3)), "3");
        assert_eq!(count_or_unknown(None), "unknown");
    }

    #[test]
    fn artifact_material_classifiers_follow_scanner_posture() {
        let rsa_private = BundleArtifactRecord {
            kind: "rsa".to_string(),
            format: "pem".to_string(),
            profile: "runtime".to_string(),
            lanes: vec!["runtime".to_string()],
            scanner_safe: false,
            path: "rsa.pem".to_string(),
            description: "runtime rsa private key".to_string(),
        };
        assert!(bundle_artifact_contains_private_key_material(&rsa_private));

        let rsa_public = BundleArtifactRecord {
            scanner_safe: true,
            ..rsa_private.clone()
        };
        assert!(!bundle_artifact_contains_private_key_material(&rsa_public));

        let webhook_secret = BundleArtifactRecord {
            kind: "webhook".to_string(),
            format: "json".to_string(),
            profile: "runtime".to_string(),
            lanes: vec!["runtime".to_string()],
            scanner_safe: false,
            path: "webhook.json".to_string(),
            description: "runtime webhook material".to_string(),
        };
        assert!(bundle_artifact_contains_symmetric_secret_material(
            &webhook_secret
        ));

        let jwk_public = BundleArtifactRecord {
            kind: "jwk".to_string(),
            format: "jwk".to_string(),
            profile: "scanner-safe".to_string(),
            lanes: vec!["scanner-safe".to_string()],
            scanner_safe: true,
            path: "jwk.json".to_string(),
            description: "scanner-safe jwk".to_string(),
        };
        assert!(!bundle_artifact_contains_symmetric_secret_material(
            &jwk_public
        ));
    }
}

fn display_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn bundle_artifact_contains_private_key_material(artifact: &BundleArtifactRecord) -> bool {
    matches!(artifact.kind.as_str(), "rsa" | "ecdsa" | "ed25519")
        && matches!(artifact.format.as_str(), "pem" | "der")
        && !artifact.scanner_safe
}

fn bundle_artifact_contains_symmetric_secret_material(artifact: &BundleArtifactRecord) -> bool {
    matches!(artifact.kind.as_str(), "hmac" | "webhook") && !artifact.scanner_safe
}

fn yes_no_unknown(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn count_or_unknown(value: Option<usize>) -> String {
    value.map_or_else(|| "unknown".to_string(), |count| count.to_string())
}

#[derive(Clone, Copy)]
struct ProfileInfo {
    profile: BundleProfile,
    title: &'static str,
    purpose: &'static str,
    required_feature: &'static str,
    scanner_posture: &'static str,
    proof_command: &'static str,
    claim: Option<&'static str>,
    docs: &'static str,
    generates: &'static [&'static str],
    proves: &'static [&'static str],
    not_proves: &'static [&'static str],
}

fn profile_info(profile: BundleProfile) -> ProfileInfo {
    match profile {
        BundleProfile::ScannerSafe => ProfileInfo {
            profile,
            title: "Scanner-safe baseline bundle",
            purpose: "baseline scanner-safe fixtures, receipts, and export handoff metadata",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "scanner-safe fixture material; generated exports still belong under target/",
            proof_command: "cargo xtask claim-proof --claim scanner-safe-fixtures",
            claim: Some("scanner-safe-fixtures"),
            docs: "docs/how-to/generate-scanner-safe-k8s-secret.md",
            generates: &[
                "rsa.jwk.json, ecdsa.jwk.json, ed25519.jwk.json",
                "hmac.jwk.json invalid symmetric JWK shape",
                "token.json near-miss token shape",
                "x509.pem public certificate fixture",
                "jwk.jwk.json and jwks.jwks.json",
                "manifest.json",
                "receipts/materialization.json",
                "receipts/audit-surface.json",
            ],
            proves: &[
                "repo policy found no committed secret-shaped fixture blobs",
                "the bundle has a manifest and audit receipts",
                "scanner-safe badge drift checks still agree with policy",
            ],
            not_proves: &[
                "every derived encoded export is safe to commit",
                "production key management",
                "scanner evasion",
                "cryptographic assurance",
            ],
        },
        BundleProfile::Tls => ProfileInfo {
            profile,
            title: "TLS contract pack",
            purpose: "TLS chain and certificate rejection fixtures",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated PEM payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask claim-proof --claim tls-contract-pack",
            claim: Some("tls-contract-pack"),
            docs: "docs/how-to/test-tls-chain-validation.md",
            generates: &[
                "certs/valid-leaf.pem",
                "certs/valid-chain.pem",
                "certs/negative-expired-leaf.pem",
                "certs/negative-not-yet-valid.pem",
                "certs/negative-wrong-hostname.pem",
                "certs/negative-untrusted-root.pem",
                "evidence/tls-profile.md",
                "manifest.json and receipts",
            ],
            proves: &[
                "documented TLS fixture files are generated",
                "positive and negative certificate paths are present",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "production PKI",
                "revocation, OCSP, certificate transparency, or mTLS",
                "browser trust-store behavior",
                "downstream verifier correctness",
            ],
        },
        BundleProfile::Oidc => ProfileInfo {
            profile,
            title: "OIDC/JWKS contract pack",
            purpose: "OIDC/JWKS validator fixtures and JWT-shaped negatives",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated token/JWKS payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask bundle-proof --profile oidc --out target/release-evidence/oidc",
            claim: Some("oidc-jwks-contract-pack"),
            docs: "docs/how-to/test-oidc-jwks-validation.md",
            generates: &[
                "jwks/valid.json",
                "jwks/negative-duplicate-kid.json",
                "jwks/negative-missing-kid.json",
                "tokens/valid-rs256.json",
                "tokens/negative-alg-none.json",
                "tokens/negative-bad-audience.json",
                "manifest.json and receipts",
            ],
            proves: &[
                "deterministic JWKS and JWT-shaped fixtures are generated",
                "documented validator negative inputs exist",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "production signing-key custody",
                "full OpenID provider behavior",
                "issuer policy",
                "downstream validator correctness",
            ],
        },
        BundleProfile::Webhook => ProfileInfo {
            profile,
            title: "Webhook contract pack",
            purpose: "HMAC webhook signature positives and negatives",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "generated request payloads stay under target/; proof receipts are metadata",
            proof_command: "cargo xtask claim-proof --claim webhook-contract-pack",
            claim: Some("webhook-contract-pack"),
            docs: "docs/how-to/test-webhook-signature-validation.md",
            generates: &[
                "requests/valid.json",
                "requests/negative-tampered-body.json",
                "requests/negative-wrong-secret.json",
                "requests/negative-stale-timestamp.json",
                "requests/negative-missing-signature.json",
                "requests/negative-malformed-signature.json",
                "evidence/webhook-profile.md",
                "manifest.json and receipts",
            ],
            proves: &[
                "deterministic HMAC verifier fixture behavior",
                "valid signature acceptance and documented rejection classes",
                "receipts and evidence docs are present",
            ],
            not_proves: &[
                "provider compatibility",
                "production secret management",
                "replay protection completeness",
                "delivery retries or transport security",
                "downstream verifier correctness",
            ],
        },
        BundleProfile::Runtime => ProfileInfo {
            profile,
            title: "Runtime bundle",
            purpose: "general runtime fixture bundle for local experimentation",
            required_feature: "uselesskey-cli default features",
            scanner_posture: "may include runtime fixture material; keep generated payloads under target/",
            proof_command: "uselesskey verify-bundle target/uselesskey-runtime",
            claim: None,
            docs: "README.md",
            generates: &[
                "rsa.jwk.json, ecdsa.jwk.json, ed25519.jwk.json",
                "hmac.jwk.json and token.json runtime material",
                "x509.pem public certificate fixture",
                "jwk.jwk.json and jwks.jwks.json",
                "manifest.json",
                "receipts/materialization.json",
                "receipts/audit-surface.json",
            ],
            proves: &[
                "the bundle can be regenerated and verified against its manifest",
                "local output shape is internally consistent",
            ],
            not_proves: &[
                "a public contract-pack claim",
                "scanner-safe commit posture",
                "production security behavior",
            ],
        },
    }
}

fn render_profiles(explain: bool) -> String {
    let mut out = String::new();
    out.push_str("Available uselesskey profiles\n\n");
    out.push_str("| Profile | Purpose | Proof/check path |\n");
    out.push_str("|---|---|---|\n");
    for profile in DISCOVERABLE_PROFILES {
        let info = profile_info(profile);
        out.push_str(&format!(
            "| `{}` | {} | `{}` |\n",
            info.profile.manifest_name(),
            info.purpose,
            info.proof_command
        ));
    }
    out.push_str("\nInstalled users generate, verify, inspect, and audit bundles with `uselesskey bundle`, `uselesskey verify-bundle`, `uselesskey inspect-bundle`, and `uselesskey audit-bundle`.\n");
    out.push_str("Use `uselesskey profile <name> --explain` for generated files, boundaries, and copyable commands.\n");

    if explain {
        out.push('\n');
        for profile in DISCOVERABLE_PROFILES {
            out.push_str(&render_profile_explanation(profile));
            out.push('\n');
        }
    }

    out
}

fn render_profile_summary(profile: BundleProfile) -> String {
    let info = profile_info(profile);
    format!(
        concat!(
            "Profile: {}\n",
            "Title: {}\n",
            "Purpose: {}\n",
            "Generate: uselesskey bundle --profile {} --out {}\n",
            "Verify: uselesskey verify-bundle {}\n",
            "Inspect: uselesskey inspect-bundle {}\n",
            "Audit: uselesskey audit-bundle {} --out {}-audit\n",
            "CI audit: uselesskey audit-bundle {} --ci --expect-profile {} --policy strict --out {}-audit\n",
            "Proof/check path: {}\n",
            "Explain: uselesskey profile {} --explain\n",
            "Bundle explain: uselesskey bundle --profile {} --explain\n",
        ),
        info.profile.manifest_name(),
        info.title,
        info.purpose,
        info.profile.manifest_name(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.profile.output_dir_hint(),
        info.profile.manifest_name(),
        info.profile.output_dir_hint(),
        info.proof_command,
        info.profile.manifest_name(),
        info.profile.manifest_name(),
    )
}

fn render_profile_explanation(profile: BundleProfile) -> String {
    let info = profile_info(profile);
    let mut out = render_profile_summary(profile);
    out.push_str(&format!("Required feature: {}\n", info.required_feature));
    out.push_str(&format!(
        "Scanner/runtime posture: {}\n",
        info.scanner_posture
    ));
    if let Some(claim) = info.claim {
        out.push_str(&format!("Claim: {claim}\n"));
    }
    out.push_str(&format!("Docs: {}\n", info.docs));
    push_list(&mut out, "\nGenerates", info.generates);
    push_list(&mut out, "\nProves", info.proves);
    push_list(&mut out, "\nDoes not prove", info.not_proves);
    out
}

fn push_list(out: &mut String, title: &str, items: &[&str]) {
    out.push_str(title);
    out.push_str(":\n");
    for item in items {
        out.push_str("- ");
        out.push_str(item);
        out.push('\n');
    }
}

#[cfg(test)]
mod profile_discovery_tests {
    use super::*;

    #[test]
    fn profile_list_includes_contract_pack_boundaries() {
        let rendered = render_profiles(false);

        assert!(rendered.contains("scanner-safe"));
        assert!(rendered.contains("tls"));
        assert!(rendered.contains("oidc"));
        assert!(rendered.contains("webhook"));
        assert!(rendered.contains("Proof/check path"));
        assert!(rendered.contains("claim-proof --claim webhook-contract-pack"));
    }

    #[test]
    fn webhook_profile_explain_mentions_negative_classes_and_limits() {
        let rendered = render_profile_explanation(BundleProfile::Webhook);

        assert!(rendered.contains("requests/valid.json"));
        assert!(rendered.contains("requests/negative-stale-timestamp.json"));
        assert!(rendered.contains("wrong-secret"));
        assert!(rendered.contains("missing-signature"));
        assert!(rendered.contains("Scanner/runtime posture"));
        assert!(rendered.contains("Proof/check path"));
        assert!(rendered.contains("provider compatibility"));
        assert!(rendered.contains("production secret management"));
    }
}

#[cfg(test)]
mod inspect_bundle_tests {
    use super::*;

    #[test]
    fn private_key_material_requires_private_key_format_and_non_scanner_safe_artifact() {
        assert!(bundle_artifact_contains_private_key_material(&record(
            "rsa", "pem", false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "rsa", "jwk", false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "token",
            "json-manifest",
            false,
        )));
        assert!(!bundle_artifact_contains_private_key_material(&record(
            "rsa", "pem", true,
        )));
    }

    #[test]
    fn symmetric_secret_material_requires_hmac_and_non_scanner_safe_artifact() {
        assert!(bundle_artifact_contains_symmetric_secret_material(&record(
            "hmac", "jwk", false,
        )));
        assert!(bundle_artifact_contains_symmetric_secret_material(&record(
            "webhook",
            "json-manifest",
            false,
        )));
        assert!(!bundle_artifact_contains_symmetric_secret_material(
            &record("token", "json-manifest", false,)
        ));
        assert!(!bundle_artifact_contains_symmetric_secret_material(
            &record("hmac", "jwk", true,)
        ));
    }

    #[test]
    fn summary_scalar_renderers_are_stable() {
        assert_eq!(yes_no_unknown(Some(true)), "yes");
        assert_eq!(yes_no_unknown(Some(false)), "no");
        assert_eq!(yes_no_unknown(None), "unknown");
        assert_eq!(count_or_unknown(Some(7)), "7");
        assert_eq!(count_or_unknown(None), "unknown");
    }

    #[test]
    fn runtime_public_jwk_outputs_are_scanner_safe() {
        for kind in [Kind::Rsa, Kind::Ecdsa, Kind::Ed25519] {
            assert!(
                runtime_entry_is_scanner_safe(kind, Format::Jwk),
                "{kind:?} jwk emits only public components",
            );
            assert!(
                runtime_entry_is_scanner_safe(kind, Format::Jwks),
                "{kind:?} jwks emits only public components",
            );
            assert!(
                !runtime_entry_is_scanner_safe(kind, Format::Pem),
                "{kind:?} pem emits private key material",
            );
            assert!(
                !runtime_entry_is_scanner_safe(kind, Format::Der),
                "{kind:?} der emits private key material",
            );
        }
        assert!(runtime_entry_is_scanner_safe(Kind::X509, Format::Pem));
        assert!(runtime_entry_is_scanner_safe(Kind::Jwk, Format::Jwk));
        assert!(runtime_entry_is_scanner_safe(Kind::Jwks, Format::Jwks));
        // Hmac jwk carries the symmetric secret in `k`; token outputs carry the value.
        assert!(!runtime_entry_is_scanner_safe(Kind::Hmac, Format::Jwk));
        assert!(!runtime_entry_is_scanner_safe(
            Kind::Token,
            Format::JsonManifest
        ));
    }

    #[test]
    fn negative_failure_class_pins_scanner_safe_token_guard() {
        let mut scanner_safe_token = record("token", "json", true);
        scanner_safe_token.path = "token.json".to_string();
        scanner_safe_token.profile = "scanner-safe".to_string();

        assert_eq!(
            negative_failure_class(&scanner_safe_token).map(|(class, _)| class),
            Some("token_near_miss")
        );

        let mut oidc_token = scanner_safe_token.clone();
        oidc_token.profile = "oidc".to_string();

        assert_eq!(negative_failure_class(&oidc_token), None);
    }

    #[test]
    fn negative_failure_class_pins_tls_taxonomy_classes() {
        let cases = [
            ("certs/negative-expired-leaf.pem", "x509_expired_leaf"),
            (
                "certs/negative-not-yet-valid.pem",
                "x509_not_yet_valid_leaf",
            ),
            ("certs/negative-wrong-hostname.pem", "x509_wrong_hostname"),
            ("certs/negative-untrusted-root.pem", "x509_untrusted_root"),
        ];

        for (path, expected_class) in cases {
            let mut artifact = record("x509", "pem", true);
            artifact.path = path.to_string();
            artifact.profile = "tls".to_string();

            assert_eq!(
                negative_failure_class(&artifact).map(|(class, _)| class),
                Some(expected_class)
            );
        }
    }

    fn record(kind: &str, format: &str, scanner_safe: bool) -> BundleArtifactRecord {
        BundleArtifactRecord {
            path: format!("{kind}.{format}"),
            kind: kind.to_string(),
            format: format.to_string(),
            profile: "test".to_string(),
            lanes: vec!["runtime".to_string(), "materialized".to_string()],
            scanner_safe,
            description: "test artifact".to_string(),
        }
    }
}

fn load_bundle_export_artifacts(bundle_dir: &Path) -> Result<Vec<ExportArtifact>> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    verify_bundle_manifest(bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", bundle_dir.display()))?;

    if manifest.artifacts.is_empty() {
        bail!(
            "bundle manifest {} does not contain artifact metadata; rerun `uselesskey bundle`",
            manifest_path.display()
        );
    }

    let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
    for record in &manifest.artifacts {
        let path = bundle_dir.join(&record.path);
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let value = String::from_utf8(bytes).with_context(|| {
            format!(
                "bundle artifact {} is not UTF-8; export payloads require text artifacts",
                path.display()
            )
        })?;
        artifacts.push(ExportArtifact {
            key: record.path.clone(),
            value,
            manifest: ManifestArtifact {
                artifact_type: ExportArtifactType::Opaque,
                source_seed: Some(manifest.seed.clone()),
                source_label: manifest.label.clone(),
                output_paths: vec![record.path.clone()],
                fingerprints: Vec::new(),
                env_var_names: Vec::new(),
                external_key_ref: None,
            },
        });
    }

    Ok(artifacts)
}

fn parse_manifest_format(raw: &str) -> Result<Format> {
    match raw {
        "pem" => Ok(Format::Pem),
        "der" => Ok(Format::Der),
        "jwk" => Ok(Format::Jwk),
        "jwks" => Ok(Format::Jwks),
        "json-manifest" | "jsonmanifest" => Ok(Format::JsonManifest),
        "bundle-dir" | "bundledir" => Ok(Format::BundleDir),
        other => bail!("unsupported bundle manifest format `{other}`"),
    }
}

fn parse_manifest_profile(raw: &str) -> Result<BundleProfile> {
    match raw {
        "scanner-safe" | "scannersafe" => Ok(BundleProfile::ScannerSafe),
        "oidc" => Ok(BundleProfile::Oidc),
        "tls" => Ok(BundleProfile::Tls),
        "webhook" => Ok(BundleProfile::Webhook),
        "runtime" => Ok(BundleProfile::Runtime),
        other => bail!("unsupported bundle manifest profile `{other}`"),
    }
}

#[derive(Clone, Copy, Debug)]
enum BundleEntry {
    Standard {
        name: &'static str,
        kind: Kind,
    },
    OidcValidJwks,
    OidcNegativeJwks {
        name: &'static str,
        variant: NegativeJwks,
        description: &'static str,
    },
    OidcValidToken,
    OidcNegativeToken {
        name: &'static str,
        variant: NegativeToken,
        description: &'static str,
    },
    TlsValidLeaf,
    TlsValidChain,
    TlsNegativeChain {
        name: &'static str,
        variant: TlsChainNegativeKind,
        description: &'static str,
    },
    TlsEvidenceDoc,
    WebhookRequest {
        name: &'static str,
        variant: WebhookRequestKind,
        description: &'static str,
    },
    WebhookEvidenceDoc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsChainNegativeKind {
    ExpiredLeaf,
    NotYetValidLeaf,
    HostnameMismatch,
    UnknownCa,
}

impl TlsChainNegativeKind {
    fn to_chain_negative(self) -> ChainNegative {
        match self {
            Self::ExpiredLeaf => ChainNegative::ExpiredLeaf,
            Self::NotYetValidLeaf => ChainNegative::NotYetValidLeaf,
            Self::HostnameMismatch => ChainNegative::HostnameMismatch {
                wrong_hostname: TLS_WRONG_HOSTNAME.to_string(),
            },
            Self::UnknownCa => ChainNegative::UnknownCa,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebhookRequestKind {
    Valid,
    TamperedBody,
    WrongSecret,
    StaleTimestamp,
    MissingSignature,
    MalformedSignature,
}

impl WebhookRequestKind {
    const fn rejection_class(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::TamperedBody => "tampered_body",
            Self::WrongSecret => "wrong_secret",
            Self::StaleTimestamp => "stale_timestamp",
            Self::MissingSignature => "missing_signature",
            Self::MalformedSignature => "malformed_signature",
        }
    }

    const fn expected_result(self) -> &'static str {
        match self {
            Self::Valid => "accept",
            Self::TamperedBody
            | Self::WrongSecret
            | Self::StaleTimestamp
            | Self::MissingSignature
            | Self::MalformedSignature => "reject",
        }
    }
}

/// Documented expected hostname for the TLS profile's valid leaf.
const TLS_EXPECTED_HOSTNAME: &str = "valid.tls.uselesskey.test";
/// Documented wrong hostname for the hostname-mismatch negative fixture.
const TLS_WRONG_HOSTNAME: &str = "wrong.tls.uselesskey.test";

impl BundleEntry {
    const fn name(self) -> &'static str {
        match self {
            Self::Standard { name, .. } => name,
            Self::OidcValidJwks => "jwks/valid",
            Self::OidcNegativeJwks { name, .. } | Self::OidcNegativeToken { name, .. } => name,
            Self::OidcValidToken => "tokens/valid-rs256",
            Self::TlsValidLeaf => "certs/valid-leaf",
            Self::TlsValidChain => "certs/valid-chain",
            Self::TlsNegativeChain { name, .. } => name,
            Self::TlsEvidenceDoc => "evidence/tls-profile",
            Self::WebhookRequest { name, .. } => name,
            Self::WebhookEvidenceDoc => "evidence/webhook-profile",
        }
    }

    const fn kind(self) -> Kind {
        match self {
            Self::Standard { kind, .. } => kind,
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Kind::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Kind::Token,
            Self::TlsValidLeaf
            | Self::TlsValidChain
            | Self::TlsNegativeChain { .. }
            | Self::TlsEvidenceDoc => Kind::X509,
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => Kind::Hmac,
        }
    }

    const fn kind_name(self) -> &'static str {
        match self {
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => "webhook",
            _ => self.kind().manifest_name(),
        }
    }

    fn preferred_format(self, requested: Format, profile: BundleProfile) -> Format {
        match self {
            Self::Standard { kind, .. } => preferred_bundle_format(kind, requested, profile),
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Format::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Format::JsonManifest,
            Self::TlsValidLeaf | Self::TlsValidChain | Self::TlsNegativeChain { .. } => Format::Pem,
            Self::TlsEvidenceDoc => Format::Pem,
            Self::WebhookRequest { .. } | Self::WebhookEvidenceDoc => Format::JsonManifest,
        }
    }

    fn file_name(self, format: Format, artifact: &Artifact) -> String {
        match self {
            Self::Standard { name, .. } => {
                let ext = format_extension(format, artifact);
                format!("{name}.{ext}")
            }
            Self::TlsValidLeaf | Self::TlsValidChain | Self::TlsNegativeChain { .. } => {
                format!("{}.pem", self.name())
            }
            Self::TlsEvidenceDoc => format!("{}.md", self.name()),
            Self::WebhookEvidenceDoc => format!("{}.md", self.name()),
            _ => format!("{}.json", self.name()),
        }
    }

    fn description(self, profile: BundleProfile) -> &'static str {
        match self {
            Self::Standard { kind, .. } => bundle_artifact_description(kind, profile),
            Self::OidcValidJwks => "OIDC valid JWKS fixture",
            Self::OidcValidToken => "OIDC valid RS256 JWT-shaped token fixture",
            Self::OidcNegativeJwks { description, .. }
            | Self::OidcNegativeToken { description, .. } => description,
            Self::TlsValidLeaf => "TLS valid leaf certificate (PEM)",
            Self::TlsValidChain => "TLS valid full chain: leaf + intermediate + root (PEM)",
            Self::TlsNegativeChain { description, .. } => description,
            Self::TlsEvidenceDoc => "TLS profile per-fixture rejection-expectation evidence",
            Self::WebhookRequest { description, .. } => description,
            Self::WebhookEvidenceDoc => "Webhook profile verifier expectation evidence",
        }
    }
}

fn bundle_entries(profile: BundleProfile) -> Vec<BundleEntry> {
    if matches!(profile, BundleProfile::Oidc) {
        return vec![
            BundleEntry::OidcValidJwks,
            BundleEntry::OidcNegativeJwks {
                name: "jwks/negative-duplicate-kid",
                variant: NegativeJwks::DuplicateKid,
                description: "OIDC negative JWKS with duplicate kid values",
            },
            BundleEntry::OidcNegativeJwks {
                name: "jwks/negative-missing-kid",
                variant: NegativeJwks::MissingKid,
                description: "OIDC negative JWKS with missing kid",
            },
            BundleEntry::OidcValidToken,
            BundleEntry::OidcNegativeToken {
                name: "tokens/negative-alg-none",
                variant: NegativeToken::AlgNone,
                description: "OIDC negative token with alg none",
            },
            BundleEntry::OidcNegativeToken {
                name: "tokens/negative-bad-audience",
                variant: NegativeToken::BadAudience,
                description: "OIDC negative token with bad audience",
            },
        ];
    }

    if matches!(profile, BundleProfile::Tls) {
        return vec![
            BundleEntry::TlsValidLeaf,
            BundleEntry::TlsValidChain,
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-expired-leaf",
                variant: TlsChainNegativeKind::ExpiredLeaf,
                description: "TLS negative chain with expired leaf (notAfter in past)",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-not-yet-valid",
                variant: TlsChainNegativeKind::NotYetValidLeaf,
                description: "TLS negative chain with not-yet-valid leaf (notBefore in future)",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-wrong-hostname",
                variant: TlsChainNegativeKind::HostnameMismatch,
                description: "TLS negative chain with leaf SAN/CN mismatch against expected hostname",
            },
            BundleEntry::TlsNegativeChain {
                name: "certs/negative-untrusted-root",
                variant: TlsChainNegativeKind::UnknownCa,
                description: "TLS negative chain anchored to an untrusted root CA",
            },
            BundleEntry::TlsEvidenceDoc,
        ];
    }

    if matches!(profile, BundleProfile::Webhook) {
        return vec![
            BundleEntry::WebhookRequest {
                name: "requests/valid",
                variant: WebhookRequestKind::Valid,
                description: "Webhook valid HMAC request",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-tampered-body",
                variant: WebhookRequestKind::TamperedBody,
                description: "Webhook negative request with modified body",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-wrong-secret",
                variant: WebhookRequestKind::WrongSecret,
                description: "Webhook negative request signed with the wrong secret",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-stale-timestamp",
                variant: WebhookRequestKind::StaleTimestamp,
                description: "Webhook negative request outside timestamp tolerance",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-missing-signature",
                variant: WebhookRequestKind::MissingSignature,
                description: "Webhook negative request missing the signature header",
            },
            BundleEntry::WebhookRequest {
                name: "requests/negative-malformed-signature",
                variant: WebhookRequestKind::MalformedSignature,
                description: "Webhook negative request with malformed signature",
            },
            BundleEntry::WebhookEvidenceDoc,
        ];
    }

    standard_bundle_entries()
        .into_iter()
        .map(|(name, kind)| BundleEntry::Standard { name, kind })
        .collect()
}

fn standard_bundle_entries() -> [(&'static str, Kind); 8] {
    [
        ("rsa", Kind::Rsa),
        ("ecdsa", Kind::Ecdsa),
        ("ed25519", Kind::Ed25519),
        ("hmac", Kind::Hmac),
        ("token", Kind::Token),
        ("x509", Kind::X509),
        ("jwk", Kind::Jwk),
        ("jwks", Kind::Jwks),
    ]
}

fn bundle_artifact_record(
    entry: BundleEntry,
    format: Format,
    path: &str,
    profile: BundleProfile,
) -> BundleArtifactRecord {
    BundleArtifactRecord {
        path: path.to_string(),
        kind: entry.kind_name().to_string(),
        format: format.manifest_name().to_string(),
        profile: profile.manifest_name().to_string(),
        lanes: vec!["runtime".to_string(), "materialized".to_string()],
        scanner_safe: bundle_entry_is_scanner_safe(entry, format, profile),
        description: entry.description(profile).to_string(),
    }
}

fn bundle_entry_is_scanner_safe(
    entry: BundleEntry,
    format: Format,
    profile: BundleProfile,
) -> bool {
    match (profile, entry) {
        (BundleProfile::ScannerSafe | BundleProfile::Oidc | BundleProfile::Tls, _) => true,
        (BundleProfile::Webhook, BundleEntry::WebhookEvidenceDoc) => true,
        (BundleProfile::Webhook, BundleEntry::WebhookRequest { .. }) => false,
        (BundleProfile::Webhook, _) => false,
        (BundleProfile::Runtime, _) => runtime_entry_is_scanner_safe(entry.kind(), format),
    }
}

// Runtime bundles emit asymmetric key kinds as either private (Pem/Der) or
// public (Jwk/Jwks) material; only the public-shaped formats are scanner-safe.
// Hmac and Token always carry secret material regardless of format.
fn runtime_entry_is_scanner_safe(kind: Kind, format: Format) -> bool {
    matches!(
        (kind, format),
        (Kind::Jwk | Kind::Jwks | Kind::X509, _)
            | (
                Kind::Rsa | Kind::Ecdsa | Kind::Ed25519,
                Format::Jwk | Format::Jwks
            )
    )
}

fn bundle_artifact_description(kind: Kind, profile: BundleProfile) -> &'static str {
    match (profile, kind) {
        (BundleProfile::ScannerSafe, Kind::Hmac) => {
            "scanner-safe symmetric JWK shape with invalid material"
        }
        (BundleProfile::ScannerSafe, Kind::Token) => {
            "scanner-safe near-miss token shape for parser tests"
        }
        (BundleProfile::ScannerSafe, Kind::X509) => "public certificate fixture",
        (BundleProfile::ScannerSafe, _) => "public fixture material",
        (BundleProfile::Runtime, Kind::Jwk | Kind::Jwks | Kind::X509) => {
            "runtime-generated public fixture material"
        }
        (BundleProfile::Runtime, _) => "runtime-generated fixture material",
        (BundleProfile::Oidc, _) => "OIDC fixture material",
        (BundleProfile::Tls, _) => "TLS contract-pack fixture material",
        (BundleProfile::Webhook, _) => "Webhook contract-pack fixture material",
    }
}

fn bundle_receipt_records(profile: BundleProfile) -> Vec<BundleReceiptRecord> {
    vec![
        BundleReceiptRecord {
            path: "receipts/materialization.json".to_string(),
            kind: "materialization".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "deterministic bundle materialization receipt".to_string(),
        },
        BundleReceiptRecord {
            path: "receipts/audit-surface.json".to_string(),
            kind: "audit-surface".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "scanner-safety and lane metadata receipt".to_string(),
        },
        BundleReceiptRecord {
            path: "receipts/bundle-verification.json".to_string(),
            kind: "bundle-verification".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "bundle verification contract receipt".to_string(),
        },
        BundleReceiptRecord {
            path: "receipts/scanner-safety.json".to_string(),
            kind: "scanner-safety".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "per-artifact scanner-safety classification receipt".to_string(),
        },
        BundleReceiptRecord {
            path: "receipts/negative-coverage.json".to_string(),
            kind: "negative-coverage".to_string(),
            profile: profile.manifest_name().to_string(),
            description: "taxonomy-backed negative fixture coverage receipt".to_string(),
        },
    ]
}

fn generate_bundle_receipt_artifact(
    kind: &str,
    seed: &str,
    label: &str,
    format: Format,
    profile: BundleProfile,
    fixture_files: &[String],
    artifacts: &[BundleArtifactRecord],
) -> Result<Artifact> {
    match kind {
        "materialization" => Ok(Artifact::Json(json!({
            "receipt": "materialization",
            "version": 1,
            "profile": profile.manifest_name(),
            "seed": seed,
            "label": label,
            "format": format.manifest_name(),
            "artifact_count": artifacts.len(),
            "files": fixture_files,
            "lanes": bundle_lanes(artifacts),
            "artifacts": artifacts,
        }))),
        "audit-surface" => {
            let scanner_safe_count = artifacts
                .iter()
                .filter(|artifact| artifact.scanner_safe)
                .count();
            Ok(Artifact::Json(json!({
                "receipt": "audit-surface",
                "version": 1,
                "profile": profile.manifest_name(),
                "scanner_safe": scanner_safe_count == artifacts.len(),
                "artifact_count": artifacts.len(),
                "scanner_safe_count": scanner_safe_count,
                "runtime_material_count": artifacts.len() - scanner_safe_count,
                "lanes": bundle_lanes(artifacts),
                "artifacts": artifacts.iter().map(|artifact| {
                    json!({
                        "path": artifact.path,
                        "kind": artifact.kind,
                        "format": artifact.format,
                        "scanner_safe": artifact.scanner_safe,
                        "description": artifact.description,
                    })
                }).collect::<Vec<_>>(),
            })))
        }
        "bundle-verification" => {
            let receipts = bundle_receipt_records(profile);
            Ok(Artifact::Json(json!({
                "receipt": "bundle-verification",
                "version": 1,
                "profile": profile.manifest_name(),
                "status": "generated",
                "verification_command": "uselesskey verify-bundle <bundle-dir>",
                "artifact_count": artifacts.len(),
                "fixture_files": fixture_files,
                "expected_receipts": receipts.iter().map(|receipt| {
                    json!({
                        "path": receipt.path,
                        "kind": receipt.kind,
                        "description": receipt.description,
                    })
                }).collect::<Vec<_>>(),
                "checks": [
                    {
                        "name": "manifest-paths",
                        "failure_class": "path_escape",
                        "detail": "manifest artifact and receipt paths must stay relative to the bundle root",
                    },
                    {
                        "name": "artifact-content",
                        "failure_class": "missing_artifact",
                        "detail": "verify-bundle regenerates profile artifacts and compares bytes",
                    },
                    {
                        "name": "receipt-content",
                        "failure_class": "missing_receipt",
                        "detail": "verify-bundle regenerates metadata-only receipts and compares bytes",
                    },
                    {
                        "name": "profile-validation",
                        "failure_class": "profile_validation_failed",
                        "detail": "verify-bundle validates the expected profile file set",
                    },
                ],
                "boundaries": [
                    "bundle-verification is local bundle consistency metadata, not repo public-claim proof",
                    "verify-bundle does not prove provider compatibility or production security",
                    "this receipt does not copy raw generated fixture payloads",
                ],
            })))
        }
        "scanner-safety" => {
            let scanner_safe_count = artifacts
                .iter()
                .filter(|artifact| artifact.scanner_safe)
                .count();
            Ok(Artifact::Json(json!({
                "receipt": "scanner-safety",
                "version": 1,
                "profile": profile.manifest_name(),
                "scanner_safe": scanner_safe_count == artifacts.len(),
                "artifact_count": artifacts.len(),
                "scanner_safe_count": scanner_safe_count,
                "runtime_material_count": artifacts.len() - scanner_safe_count,
                "artifacts": artifacts.iter().map(|artifact| {
                    json!({
                        "path": artifact.path,
                        "kind": artifact.kind,
                        "format": artifact.format,
                        "scanner_safe": artifact.scanner_safe,
                        "runtime_material": !artifact.scanner_safe,
                        "lanes": artifact.lanes,
                        "description": artifact.description,
                    })
                }).collect::<Vec<_>>(),
                "boundaries": [
                    "scanner_safe=true means uselesskey classifies the generated artifact as scanner-safe fixture material",
                    "runtime_material=true means keep the generated artifact under an explicit output directory such as target/",
                    "scanner-safety metadata is not scanner evasion, production secret handling, or provider compatibility proof",
                ],
            })))
        }
        "negative-coverage" => {
            let coverage = artifacts
                .iter()
                .filter_map(negative_coverage_entry)
                .collect::<Vec<_>>();
            Ok(Artifact::Json(json!({
                "receipt": "negative-coverage",
                "version": 1,
                "profile": profile.manifest_name(),
                "negative_count": coverage.len(),
                "coverage": coverage,
                "boundaries": [
                    "negative coverage records generated fixture classes, not downstream verifier correctness",
                    "failure classes map to USELESSKEY-SPEC-0016 taxonomy IDs",
                    "this receipt is metadata-only and does not copy generated fixture payloads",
                ],
            })))
        }
        other => bail!("unsupported bundle receipt `{other}`"),
    }
}

fn negative_coverage_entry(artifact: &BundleArtifactRecord) -> Option<serde_json::Value> {
    let (failure_class, expected_failure) = negative_failure_class(artifact)?;
    Some(json!({
        "path": artifact.path,
        "kind": artifact.kind,
        "failure_class": failure_class,
        "expected_failure": expected_failure,
        "scanner_safe": artifact.scanner_safe,
        "runtime_material": !artifact.scanner_safe,
        "description": artifact.description,
    }))
}

fn negative_failure_class(artifact: &BundleArtifactRecord) -> Option<(&'static str, &'static str)> {
    match artifact.path.as_str() {
        "token.json" if artifact.profile == "scanner-safe" => Some((
            "token_near_miss",
            "parser or application policy rejects token shape",
        )),
        "jwks/negative-duplicate-kid.json" => {
            Some(("jwks_duplicate_kid", "ambiguous key selection"))
        }
        "jwks/negative-missing-kid.json" => {
            Some(("jwks_missing_kid", "key selection cannot identify the key"))
        }
        "tokens/negative-alg-none.json" => {
            Some(("jwt_alg_none", "verifier policy rejects unsigned algorithm"))
        }
        "tokens/negative-bad-audience.json" => {
            Some(("jwt_bad_audience", "claim validation rejects token"))
        }
        "certs/negative-expired-leaf.pem" => {
            Some(("x509_expired_leaf", "verifier rejects expiration"))
        }
        "certs/negative-not-yet-valid.pem" => {
            Some(("x509_not_yet_valid_leaf", "verifier rejects not-before"))
        }
        "certs/negative-wrong-hostname.pem" => {
            Some(("x509_wrong_hostname", "hostname validation rejects"))
        }
        "certs/negative-untrusted-root.pem" => Some((
            "x509_untrusted_root",
            "path validation rejects untrusted root",
        )),
        "requests/negative-tampered-body.json" => {
            Some(("webhook_tampered_body", "canonical signature check rejects"))
        }
        "requests/negative-wrong-secret.json" => {
            Some(("webhook_wrong_secret", "signature verification rejects"))
        }
        "requests/negative-stale-timestamp.json" => {
            Some(("webhook_stale_timestamp", "replay-window policy rejects"))
        }
        "requests/negative-missing-signature.json" => Some((
            "webhook_missing_signature",
            "verifier rejects missing credential",
        )),
        "requests/negative-malformed-signature.json" => Some((
            "webhook_malformed_signature",
            "parser or verifier rejects signature encoding",
        )),
        _ => None,
    }
}

fn bundle_lanes(artifacts: &[BundleArtifactRecord]) -> Vec<String> {
    let mut lanes = Vec::new();
    for artifact in artifacts {
        for lane in &artifact.lanes {
            if !lanes.contains(lane) {
                lanes.push(lane.clone());
            }
        }
    }
    lanes
}

fn preferred_bundle_format(kind: Kind, requested: Format, profile: BundleProfile) -> Format {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return match kind {
            Kind::Token => Format::JsonManifest,
            Kind::X509 => Format::Pem,
            Kind::Jwks => Format::Jwks,
            Kind::Rsa | Kind::Ecdsa | Kind::Ed25519 | Kind::Hmac | Kind::Jwk => Format::Jwk,
        };
    }

    match (kind, requested) {
        (Kind::Token, _) => Format::JsonManifest,
        (Kind::X509, Format::Jwk | Format::Jwks) => Format::Pem,
        (Kind::Hmac, Format::Pem) => Format::Der,
        (Kind::Jwk, _) => Format::Jwk,
        (Kind::Jwks, _) => Format::Jwks,
        _ => requested,
    }
}

fn generate_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
    profile: BundleProfile,
) -> Result<Artifact> {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return generate_scanner_safe_bundle_artifact(fx, kind, name, label, format);
    }

    generate_artifact(fx, kind, label, format)
}

fn generate_bundle_entry_artifact(
    fx: &Factory,
    entry: BundleEntry,
    label: &str,
    format: Format,
    profile: BundleProfile,
) -> Result<Artifact> {
    match entry {
        BundleEntry::Standard { name, kind } => {
            generate_bundle_artifact(fx, kind, name, label, format, profile)
        }
        BundleEntry::OidcValidJwks => {
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(
                    fx.rsa(label, RsaSpec::rs256()).public_jwks_json(),
                ))
            } else {
                unsupported(Kind::Jwks, format)
            }
        }
        BundleEntry::OidcNegativeJwks { variant, .. } => {
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(
                    fx.rsa(label, RsaSpec::rs256())
                        .public_jwks()
                        .negative_value(variant),
                ))
            } else {
                unsupported(Kind::Jwks, format)
            }
        }
        BundleEntry::OidcValidToken => {
            let token = fx.token(label, TokenSpec::oauth_access_token());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "profile": "oidc",
                    "alg": "RS256",
                    "value": token.value(),
                })))
            } else {
                unsupported(Kind::Token, format)
            }
        }
        BundleEntry::OidcNegativeToken { variant, .. } => {
            let token = fx.token(label, TokenSpec::oauth_access_token());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "profile": "oidc",
                    "negative": variant.variant_name(),
                    "value": token.negative_value(variant),
                })))
            } else {
                unsupported(Kind::Token, format)
            }
        }
        BundleEntry::TlsValidLeaf => {
            let chain = tls_valid_chain(fx, label);
            Ok(Artifact::Text(chain.leaf_cert_pem().to_string()))
        }
        BundleEntry::TlsValidChain => {
            let chain = tls_valid_chain(fx, label);
            Ok(Artifact::Text(chain.full_chain_pem()))
        }
        BundleEntry::TlsNegativeChain { variant, .. } => {
            let valid = tls_valid_chain(fx, label);
            let negative = valid.negative(variant.to_chain_negative());
            Ok(Artifact::Text(negative.leaf_cert_pem().to_string()))
        }
        BundleEntry::TlsEvidenceDoc => Ok(Artifact::Text(render_tls_evidence_markdown())),
        BundleEntry::WebhookRequest { variant, .. } => {
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(generate_webhook_request_fixture(
                    fx, label, variant,
                )))
            } else {
                unsupported(Kind::Hmac, format)
            }
        }
        BundleEntry::WebhookEvidenceDoc => Ok(Artifact::Text(render_webhook_evidence_markdown())),
    }
}

fn tls_valid_chain(fx: &Factory, label: &str) -> X509Chain {
    fx.x509_chain(label, ChainSpec::new(TLS_EXPECTED_HOSTNAME))
}

fn render_tls_evidence_markdown() -> String {
    let mut out = String::new();
    out.push_str("# TLS contract-pack profile evidence\n\n");
    out.push_str(
        "Per-fixture role and rejection-class expectations for the TLS contract\n\
         pack generated by `uselesskey bundle --profile tls`. See\n\
         `docs/release/v0.8.0-tls-profile-design.md` for the full design.\n\n",
    );
    out.push_str(&format!("Expected hostname: `{TLS_EXPECTED_HOSTNAME}`\n"));
    out.push_str(&format!(
        "Hostname-mismatch wrong hostname: `{TLS_WRONG_HOSTNAME}`\n\n",
    ));
    out.push_str("| File | Role | Failure class |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| `certs/valid-leaf.pem` | Valid leaf signed by the bundle's intermediate | (none - happy path) |\n");
    out.push_str("| `certs/valid-chain.pem` | Full chain: leaf + intermediate + root | (none - happy path) |\n");
    out.push_str(
        "| `certs/negative-expired-leaf.pem` | Leaf with notAfter in the past | expired |\n",
    );
    out.push_str("| `certs/negative-not-yet-valid.pem` | Leaf with notBefore in the future | not yet valid |\n");
    out.push_str("| `certs/negative-wrong-hostname.pem` | Leaf SAN/CN does not match expected hostname | hostname mismatch |\n");
    out.push_str("| `certs/negative-untrusted-root.pem` | Leaf chained to an untrusted root CA | unknown CA |\n");
    out
}

fn generate_webhook_request_fixture(
    fx: &Factory,
    label: &str,
    variant: WebhookRequestKind,
) -> serde_json::Value {
    let valid = fx.webhook_stripe(label, WebhookPayloadSpec::Canonical);
    let mut headers = valid.headers.clone();
    let mut body = valid.payload.clone();
    let mut timestamp = valid.timestamp;

    match variant {
        WebhookRequestKind::Valid => {}
        WebhookRequestKind::TamperedBody => {
            body.push('\n');
        }
        WebhookRequestKind::WrongSecret => {
            let wrong = valid.near_miss_wrong_secret();
            headers = wrong.headers;
            timestamp = wrong.timestamp;
        }
        WebhookRequestKind::StaleTimestamp => {
            let stale = valid.near_miss_stale_timestamp(300);
            headers = stale.headers;
            timestamp = stale.timestamp;
        }
        WebhookRequestKind::MissingSignature => {
            headers.remove("Stripe-Signature");
        }
        WebhookRequestKind::MalformedSignature => {
            headers.insert(
                "Stripe-Signature".to_string(),
                format!("t={timestamp},v1=not-a-hex-signature"),
            );
        }
    }

    json!({
        "method": "POST",
        "path": "/webhooks/uselesskey",
        "timestamp": timestamp,
        "body": body,
        "headers": headers,
        "expected_result": variant.expected_result(),
        "rejection_class": variant.rejection_class(),
        "profile": "webhook",
        "signature_profile": "stripe-shaped-hmac-sha256",
        "verifier_secret": valid.secret,
        "claim_boundary": "Deterministic HMAC verifier fixture; not provider compatibility or production secret management proof."
    })
}

fn render_webhook_evidence_markdown() -> String {
    let mut out = String::new();
    out.push_str("# Webhook contract-pack profile evidence\n\n");
    out.push_str(
        "Per-fixture verifier expectations for the webhook contract pack\n\
         generated by `uselesskey bundle --profile webhook`. The fixtures are\n\
         provider-shaped HMAC-SHA256 requests, not provider compatibility\n\
         claims.\n\n",
    );
    out.push_str("Verifier path: `POST /webhooks/uselesskey`\n");
    out.push_str("Timestamp tolerance used by proof: `300` seconds\n\n");
    out.push_str("| File | Expected result | Rejection class |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| `requests/valid.json` | accept | valid |\n");
    out.push_str("| `requests/negative-tampered-body.json` | reject | tampered_body |\n");
    out.push_str("| `requests/negative-wrong-secret.json` | reject | wrong_secret |\n");
    out.push_str("| `requests/negative-stale-timestamp.json` | reject | stale_timestamp |\n");
    out.push_str("| `requests/negative-missing-signature.json` | reject | missing_signature |\n");
    out.push_str(
        "| `requests/negative-malformed-signature.json` | reject | malformed_signature |\n\n",
    );
    out.push_str("Boundary: proves deterministic HMAC webhook verifier behavior for fixture requests; does not prove provider compatibility, replay protection completeness, transport security, or production secret management.\n");
    out
}

fn generate_scanner_safe_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
) -> Result<Artifact> {
    match kind {
        Kind::Hmac => {
            if matches!(format, Format::Jwk) {
                Ok(Artifact::Json(json!({
                    "kty": "oct",
                    "use": "sig",
                    "alg": "HS256",
                    "kid": format!("{label}-{name}"),
                    "k": "not_base64url!*",
                })))
            } else {
                unsupported(kind, format)
            }
        }
        Kind::Token => {
            let token = fx.token(label, TokenSpec::api_key());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "negative": NegativeToken::NearMissApiKey.variant_name(),
                    "value": token.negative_value(NegativeToken::NearMissApiKey),
                })))
            } else {
                unsupported(kind, format)
            }
        }
        _ => generate_artifact(fx, kind, label, format),
    }
}

fn generate_artifact(fx: &Factory, kind: Kind, label: &str, format: Format) -> Result<Artifact> {
    match kind {
        Kind::Rsa => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Ecdsa => {
            let kp = fx.ecdsa(label, EcdsaSpec::es256());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Ed25519 => {
            let kp = fx.ed25519(label, Ed25519Spec::new());
            match format {
                Format::Pem => Ok(Artifact::Text(kp.private_key_pkcs8_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(kp.private_key_pkcs8_der().to_vec())),
                Format::Jwk => Ok(Artifact::Json(kp.public_jwk_json())),
                Format::Jwks => Ok(Artifact::Json(kp.public_jwks_json())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Hmac => {
            let sec = fx.hmac(label, HmacSpec::hs256());
            match format {
                Format::Der => Ok(Artifact::Binary(sec.secret_bytes().to_vec())),
                Format::Jwk => Ok(Artifact::Json(sec.jwk().to_value())),
                Format::Jwks => Ok(Artifact::Json(sec.jwks().to_value())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Token => {
            let token = fx.token(label, TokenSpec::api_key());
            match format {
                Format::Pem => Ok(Artifact::Text(token.value().to_string())),
                Format::JsonManifest => Ok(Artifact::Json(
                    json!({"kind":"token","label":label,"value":token.value()}),
                )),
                _ => unsupported(kind, format),
            }
        }
        Kind::X509 => {
            let cert = fx.x509_self_signed(label, X509Spec::self_signed(label));
            match format {
                Format::Pem => Ok(Artifact::Text(cert.cert_pem().to_string())),
                Format::Der => Ok(Artifact::Binary(cert.cert_der().to_vec())),
                _ => unsupported(kind, format),
            }
        }
        Kind::Jwk => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            if matches!(format, Format::Jwk) {
                Ok(Artifact::Json(kp.public_jwk_json()))
            } else {
                unsupported(kind, format)
            }
        }
        Kind::Jwks => {
            let kp = fx.rsa(label, RsaSpec::rs256());
            if matches!(format, Format::Jwks) {
                Ok(Artifact::Json(kp.public_jwks_json()))
            } else {
                unsupported(kind, format)
            }
        }
    }
}

fn unsupported(kind: Kind, format: Format) -> Result<Artifact> {
    bail!("unsupported format {format:?} for kind {kind:?}")
}

fn emit_artifact(artifact: &Artifact, out: Option<&Path>) -> Result<()> {
    if let Some(path) = out {
        write_artifact_to_path(artifact, path)
    } else {
        write_artifact_to_stdout(artifact)
    }
}

fn write_artifact_to_stdout(artifact: &Artifact) -> Result<()> {
    let mut out = io::stdout().lock();
    match artifact {
        Artifact::Text(t) => out.write_all(t.as_bytes())?,
        Artifact::Binary(b) => out.write_all(b)?,
        Artifact::Json(v) => {
            serde_json::to_writer_pretty(&mut out, v)?;
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    Ok(())
}

fn artifact_bytes(artifact: &Artifact) -> Result<Vec<u8>> {
    match artifact {
        Artifact::Text(t) => Ok(t.as_bytes().to_vec()),
        Artifact::Binary(b) => Ok(b.clone()),
        Artifact::Json(v) => Ok(serde_json::to_vec_pretty(v)?),
    }
}

fn write_artifact_to_path(artifact: &Artifact, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, artifact_bytes(artifact)?)?;
    Ok(())
}

fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    match path {
        Some(p) if p != Path::new("-") => {
            buf = fs::read(p).with_context(|| format!("failed to read {}", p.display()))?
        }
        _ => {
            io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .context("failed reading stdin")?;
        }
    }
    Ok(buf)
}

fn format_extension(format: Format, artifact: &Artifact) -> &'static str {
    match format {
        Format::Pem => "pem",
        Format::Der => "der",
        Format::Jwk => "jwk.json",
        Format::Jwks => "jwks.json",
        Format::JsonManifest => "json",
        Format::BundleDir => match artifact {
            Artifact::Binary(_) => "bin",
            Artifact::Json(_) => "json",
            Artifact::Text(_) => "txt",
        },
    }
}

fn detect_kind(text: &str) -> &'static str {
    if text.contains("BEGIN CERTIFICATE") {
        "x509"
    } else if text.contains("BEGIN PRIVATE KEY") {
        "private_key"
    } else {
        detect_json_kind(text).unwrap_or("unknown")
    }
}

fn detect_json_kind(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }

    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let object = value.as_object()?;
    if object
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .is_some()
    {
        Some("jwks")
    } else if object
        .get("kty")
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        Some("jwk")
    } else {
        None
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct BundleManifest {
    version: u32,
    #[serde(default = "default_bundle_profile")]
    profile: String,
    seed: String,
    label: String,
    format: String,
    files: Vec<String>,
    #[serde(default)]
    artifacts: Vec<BundleArtifactRecord>,
    #[serde(default)]
    receipts: Vec<BundleReceiptRecord>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct BundleArtifactRecord {
    path: String,
    kind: String,
    format: String,
    profile: String,
    lanes: Vec<String>,
    scanner_safe: bool,
    description: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
struct BundleReceiptRecord {
    path: String,
    kind: String,
    profile: String,
    description: String,
}

fn default_bundle_profile() -> String {
    "runtime".to_string()
}

#[derive(Clone, Debug, Serialize)]
struct BundleAudit {
    version: u32,
    status: String,
    bundle_path: String,
    profile: String,
    manifest_version: u32,
    manifest_path: String,
    artifact_count: usize,
    receipt_count: usize,
    scanner_safe_count: usize,
    runtime_material_count: usize,
    files: Vec<String>,
    artifacts: Vec<BundleAuditArtifact>,
    receipts: Vec<BundleReceiptRecord>,
    missing_files: Vec<String>,
    unexpected_files: Vec<String>,
    checks: Vec<BundleAuditCheck>,
    boundaries: Vec<String>,
    does_not_prove: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct BundleAuditArtifact {
    path: String,
    kind: String,
    format: String,
    scanner_safe: bool,
    runtime_material: bool,
    description: String,
}

#[derive(Clone, Debug, Serialize)]
struct BundleAuditCheck {
    name: String,
    status: String,
    failure_class: String,
    detail: String,
}

impl BundleAuditCheck {
    fn pass(name: &str, failure_class: &str, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "pass".to_string(),
            failure_class: failure_class.to_string(),
            detail: detail.to_string(),
        }
    }

    fn fail(name: &str, failure_class: &str, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            status: "fail".to_string(),
            failure_class: failure_class.to_string(),
            detail: detail.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    version: u32,
    status: String,
    cli_version: String,
    current_dir: String,
    known_profiles: Vec<String>,
    checks: Vec<DoctorCheck>,
    next_steps: Vec<String>,
    boundaries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: String,
    detail: String,
}

impl DoctorCheck {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "pass".to_string(),
            detail: detail.into(),
        }
    }

    fn fail(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status: "fail".to_string(),
            detail: detail.into(),
        }
    }
}

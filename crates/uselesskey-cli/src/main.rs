#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
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
use uselesskey_x509::{X509FactoryExt, X509Spec};

#[derive(Parser, Debug)]
#[command(name = "uselesskey", about = "Deterministic fixture generation CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Generate(GenerateArgs),
    Bundle(BundleArgs),
    VerifyBundle(VerifyBundleArgs),
    InspectBundle(InspectBundleArgs),
    Export(ExportArgs),
    Inspect(InspectArgs),
    Materialize(MaterializeArgs),
    Verify(VerifyArgs),
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
struct BundleArgs {
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    seed: String,
    #[arg(long, default_value = "bundle")]
    label: String,
    #[arg(long, default_value = "jwk")]
    format: Format,
    #[arg(long, default_value = "scanner-safe")]
    profile: BundleProfile,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct VerifyBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    bundle_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
struct InspectBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    bundle_dir: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
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
    Runtime,
}

impl BundleProfile {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Runtime => "runtime",
        }
    }
}

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
        Commands::Bundle(args) => run_bundle(args),
        Commands::VerifyBundle(args) => run_verify_bundle(args),
        Commands::InspectBundle(args) => run_inspect_bundle(args),
        Commands::Export(args) => run_export(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Materialize(args) => run_materialize(args),
        Commands::Verify(args) => run_verify(args),
    }
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let fx = Factory::deterministic_from_str(&args.seed);
    let artifact = generate_artifact(&fx, args.kind, &args.label, args.format)?;
    emit_artifact(&artifact, args.out.as_deref())
}

fn run_bundle(args: BundleArgs) -> Result<()> {
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
    let manifest_path = args.bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    let files = verify_bundle_manifest(&args.bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", args.bundle_dir.display()))?;

    emit_artifact(
        &Artifact::Json(json!({
            "verify_bundle": {
                "status": "ok",
                "bundle_dir": args.bundle_dir,
                "manifest": manifest_path,
                "count": files.len(),
                "files": files,
            }
        })),
        None,
    )
}

fn run_inspect_bundle(args: InspectBundleArgs) -> Result<()> {
    let manifest_path = args.bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    let files = verify_bundle_manifest(&args.bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", args.bundle_dir.display()))?;
    let summary = render_bundle_inspection_summary(&manifest, files.len());

    emit_artifact(&Artifact::Text(summary), args.out.as_deref())
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
        expected_files.push(file_name);
        expected_artifacts.push(bundle_artifact_record(
            entry,
            bundle_format,
            expected_files.last().expect("just pushed"),
            profile,
        ));
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

    format!(
        concat!(
            "Bundle profile: {}\n",
            "Artifacts: {}\n",
            "Verified files: {}\n",
            "Scanner-safe: {}\n",
            "Private key material: {}\n",
            "Symmetric secret material: {}\n",
            "Runtime material artifacts: {}\n",
            "Verification: ok\n",
            "Receipts: {}\n",
        ),
        manifest.profile,
        artifact_count,
        verified_file_count,
        yes_no_unknown(scanner_safe),
        yes_no_unknown(private_key_material),
        yes_no_unknown(symmetric_secret_material),
        count_or_unknown(runtime_material_count),
        receipts
    )
}

fn bundle_artifact_contains_private_key_material(artifact: &BundleArtifactRecord) -> bool {
    matches!(artifact.kind.as_str(), "rsa" | "ecdsa" | "ed25519")
        && matches!(artifact.format.as_str(), "pem" | "der")
        && !artifact.scanner_safe
}

fn bundle_artifact_contains_symmetric_secret_material(artifact: &BundleArtifactRecord) -> bool {
    artifact.kind == "hmac" && !artifact.scanner_safe
}

fn yes_no_unknown(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn count_or_unknown(value: Option<usize>) -> String {
    value.map_or_else(|| "unknown".to_string(), |count| count.to_string())
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
}

impl BundleEntry {
    const fn name(self) -> &'static str {
        match self {
            Self::Standard { name, .. } => name,
            Self::OidcValidJwks => "jwks/valid",
            Self::OidcNegativeJwks { name, .. } | Self::OidcNegativeToken { name, .. } => name,
            Self::OidcValidToken => "tokens/valid-rs256",
        }
    }

    const fn kind(self) -> Kind {
        match self {
            Self::Standard { kind, .. } => kind,
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Kind::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Kind::Token,
        }
    }

    fn preferred_format(self, requested: Format, profile: BundleProfile) -> Format {
        match self {
            Self::Standard { kind, .. } => preferred_bundle_format(kind, requested, profile),
            Self::OidcValidJwks | Self::OidcNegativeJwks { .. } => Format::Jwks,
            Self::OidcValidToken | Self::OidcNegativeToken { .. } => Format::JsonManifest,
        }
    }

    fn file_name(self, format: Format, artifact: &Artifact) -> String {
        match self {
            Self::Standard { name, .. } => {
                let ext = format_extension(format, artifact);
                format!("{name}.{ext}")
            }
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
        kind: entry.kind().manifest_name().to_string(),
        format: format.manifest_name().to_string(),
        profile: profile.manifest_name().to_string(),
        lanes: vec!["runtime".to_string(), "materialized".to_string()],
        scanner_safe: bundle_artifact_is_scanner_safe(entry.kind(), profile),
        description: entry.description(profile).to_string(),
    }
}

fn bundle_artifact_is_scanner_safe(kind: Kind, profile: BundleProfile) -> bool {
    match profile {
        BundleProfile::ScannerSafe | BundleProfile::Oidc => true,
        BundleProfile::Runtime => matches!(kind, Kind::Jwk | Kind::Jwks | Kind::X509),
    }
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
        other => bail!("unsupported bundle receipt `{other}`"),
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
    }
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

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BundleArtifactRecord {
    path: String,
    kind: String,
    format: String,
    profile: String,
    lanes: Vec<String>,
    scanner_safe: bool,
    description: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BundleReceiptRecord {
    path: String,
    kind: String,
    profile: String,
    description: String,
}

fn default_bundle_profile() -> String {
    "runtime".to_string()
}

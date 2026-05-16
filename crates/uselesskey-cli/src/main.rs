#![forbid(unsafe_code)]

mod srp;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use uselesskey_cli::{
    emit_include_bytes_module, load_materialize_manifest, materialize_manifest_to_dir,
    render_k8s_secret_yaml, render_vault_kv_json,
};
use uselesskey_core::Factory;

use srp::artifact::{Artifact, detect_kind, emit_artifact, read_input, write_artifact_to_path};
use srp::bundle::{
    BundleManifest, bundle_artifact_record, bundle_entries, bundle_receipt_records,
    generate_artifact, generate_bundle_entry_artifact, generate_bundle_receipt_artifact,
    load_bundle_export_artifacts, load_bundle_manifest, render_bundle_inspection_summary,
    verify_bundle_manifest,
};
use srp::profiles::{render_profile_explanation, render_profile_summary, render_profiles};
use srp::types::{BundleProfile, Format, Kind};

#[derive(Parser, Debug)]
#[command(name = "uselesskey", about = "Deterministic fixture generation CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Generate(GenerateArgs),
    Profiles(ProfilesArgs),
    Profile(ProfileArgs),
    Bundle(BundleArgs),
    VerifyBundle(VerifyBundleArgs),
    InspectBundle(InspectBundleArgs),
    Export(ExportArgs),
    Inspect(InspectArgs),
    Materialize(MaterializeArgs),
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
    #[arg(long)]
    explain: bool,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate(args) => run_generate(args),
        Commands::Profiles(args) => run_profiles(args),
        Commands::Profile(args) => run_profile(args),
        Commands::Bundle(args) => run_bundle(args),
        Commands::VerifyBundle(args) => run_verify_bundle(args),
        Commands::InspectBundle(args) => run_inspect_bundle(args),
        Commands::Export(args) => run_export(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Materialize(args) => run_materialize(args),
        Commands::Verify(args) => run_verify(args),
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

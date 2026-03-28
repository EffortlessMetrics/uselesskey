#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use uselesskey_cli::{BundleEntry, ExportBundleSpec, TargetFormat, exporters};

#[derive(Debug, Parser)]
#[command(name = "uselesskey", about = "Export uselesskey fixtures for downstream tooling")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Export a fixture bundle to one of the portable formats.
    Bundle(BundleArgs),
    /// Focused export commands.
    #[command(subcommand)]
    Export(ExportCommands),
}

#[derive(Debug, Parser)]
struct BundleArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, value_enum)]
    format: FormatArg,
    #[arg(long = "entry", value_parser = parse_entry)]
    entries: Vec<BundleEntry>,
    #[arg(long)]
    source_receipt: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum ExportCommands {
    /// Export Kubernetes Secret YAML.
    K8s(BundleArgs),
    /// Export a Vault KV JSON payload.
    VaultKvJson(BundleArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    FlatFiles,
    EnvDir,
    DotEnvFragment,
    KubernetesSecretYaml,
    SopsYamlSkeleton,
    VaultKvJson,
    GenericManifest,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Bundle(args) => run_bundle(args),
        Commands::Export(ExportCommands::K8s(mut args)) => {
            args.format = FormatArg::KubernetesSecretYaml;
            run_bundle(args)
        }
        Commands::Export(ExportCommands::VaultKvJson(mut args)) => {
            args.format = FormatArg::VaultKvJson;
            run_bundle(args)
        }
    }
}

fn run_bundle(args: BundleArgs) -> anyhow::Result<()> {
    let spec = ExportBundleSpec {
        bundle_name: args.name,
        outputs: vec![args.output_dir],
        target_format: map_format(args.format),
        env_names: Default::default(),
        secret_names: Default::default(),
    };

    let result = exporters::export_bundle(&spec, &args.entries, args.source_receipt.as_deref())
        .context("failed to export bundle")?;

    println!("manifest: {}", result.manifest_path.display());
    for written in result.written_files {
        println!("wrote {} ({} bytes)", written.path.display(), written.bytes);
    }
    Ok(())
}

fn parse_entry(s: &str) -> Result<BundleEntry, String> {
    let (name, value) = s
        .split_once('=')
        .ok_or_else(|| "entry must be name=value".to_string())?;
    if name.is_empty() {
        return Err("entry name cannot be empty".to_string());
    }
    Ok(BundleEntry {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn map_format(format: FormatArg) -> TargetFormat {
    match format {
        FormatArg::FlatFiles => TargetFormat::FlatFiles,
        FormatArg::EnvDir => TargetFormat::EnvDir,
        FormatArg::DotEnvFragment => TargetFormat::DotEnvFragment,
        FormatArg::KubernetesSecretYaml => TargetFormat::KubernetesSecretYaml,
        FormatArg::SopsYamlSkeleton => TargetFormat::SopsYamlSkeleton,
        FormatArg::VaultKvJson => TargetFormat::VaultKvJson,
        FormatArg::GenericManifest => TargetFormat::GenericManifest,
    }
}

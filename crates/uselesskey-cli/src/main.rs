#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use uselesskey_cli::{ExportBundleSpec, ExportEntry, ExportTarget, export_bundle};

#[derive(Debug, Parser)]
#[command(name = "uselesskey")]
#[command(about = "Generate export manifests for uselesskey fixture handoff")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Bundle(BundleArgs),
    Export(ExportArgs),
}

#[derive(Debug, Parser)]
struct BundleArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, value_enum)]
    target: TargetArg,
    #[arg(long = "entry", required = true, value_parser = parse_entry)]
    entries: Vec<ExportEntry>,
}

#[derive(Debug, Parser)]
struct ExportArgs {
    #[command(subcommand)]
    command: ExportSubcommand,
}

#[derive(Debug, Subcommand)]
enum ExportSubcommand {
    K8s(ProviderArgs),
    VaultKvJson(ProviderArgs),
}

#[derive(Debug, Parser)]
struct ProviderArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long = "entry", required = true, value_parser = parse_entry)]
    entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone, ValueEnum)]
enum TargetArg {
    FlatFileBundle,
    Envdir,
    Dotenv,
    K8s,
    Sops,
    VaultKvJson,
    Manifest,
}

fn parse_entry(value: &str) -> Result<ExportEntry, String> {
    let (left, payload) = value
        .split_once('=')
        .ok_or_else(|| "entry must be id:file_name=value".to_string())?;
    let (id, file_name) = left
        .split_once(':')
        .ok_or_else(|| "entry must be id:file_name=value".to_string())?;

    Ok(ExportEntry {
        id: id.to_string(),
        file_name: file_name.to_string(),
        value: payload.to_string(),
        env_var_name: None,
        secret_name: None,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let spec = match cli.command {
        Commands::Bundle(args) => ExportBundleSpec {
            bundle_name: args.name,
            target: map_target(args.target),
            output_dir: args.output_dir,
            entries: args.entries,
        },
        Commands::Export(args) => match args.command {
            ExportSubcommand::K8s(args) => ExportBundleSpec {
                bundle_name: args.name,
                target: ExportTarget::KubernetesSecretYaml,
                output_dir: args.output_dir,
                entries: args.entries,
            },
            ExportSubcommand::VaultKvJson(args) => ExportBundleSpec {
                bundle_name: args.name,
                target: ExportTarget::VaultKvJsonPayload,
                output_dir: args.output_dir,
                entries: args.entries,
            },
        },
    };

    let result = export_bundle(&spec).context("failed to export bundle")?;
    println!("manifest: {}", result.manifest_path.display());
    for path in result.written_files {
        println!("written: {}", path.display());
    }

    Ok(())
}

fn map_target(target: TargetArg) -> ExportTarget {
    match target {
        TargetArg::FlatFileBundle => ExportTarget::FlatFileBundle,
        TargetArg::Envdir => ExportTarget::EnvDir,
        TargetArg::Dotenv => ExportTarget::DotEnvFragment,
        TargetArg::K8s => ExportTarget::KubernetesSecretYaml,
        TargetArg::Sops => ExportTarget::SopsReadyYamlSkeleton,
        TargetArg::VaultKvJson => ExportTarget::VaultKvJsonPayload,
        TargetArg::Manifest => ExportTarget::GenericManifest,
    }
}

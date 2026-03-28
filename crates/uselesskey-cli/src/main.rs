#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uselesskey_cli::{ExportBundleSpec, ExportTargetFormat, export_bundle, parse_entries};

#[derive(Debug, Parser)]
#[command(name = "uselesskey", version, about = "Export uselesskey fixtures for existing secret toolchains")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Export a fixture bundle in one of the portable formats.
    Bundle {
        /// Human-readable bundle name.
        #[arg(long)]
        name: String,
        /// Output directory where files/manifests are written.
        #[arg(long)]
        out_dir: PathBuf,
        /// Export format.
        #[arg(long, value_enum)]
        format: ExportTargetFormat,
        /// Repeated entries in KEY=VALUE form.
        #[arg(long = "entry")]
        entries: Vec<String>,
        /// Optional source fixture receipt path for coherence.
        #[arg(long)]
        source_receipt: Option<PathBuf>,
    },
    /// Convenience wrapper for Kubernetes Secret YAML exports.
    Export {
        #[command(subcommand)]
        command: ExportCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ExportCommands {
    /// Emit Kubernetes Secret YAML plus manifest references.
    K8s {
        #[arg(long)]
        name: String,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long = "entry")]
        entries: Vec<String>,
    },
    /// Emit Vault KV JSON payload plus manifest references.
    VaultKvJson {
        #[arg(long)]
        name: String,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        mount: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long = "entry")]
        entries: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Bundle {
            name,
            out_dir,
            format,
            entries,
            source_receipt,
        } => {
            let outputs = parse_entries(&entries)?;
            let spec = ExportBundleSpec {
                bundle_name: name,
                out_dir,
                target_format: format,
                outputs,
                env_var_names: BTreeMap::new(),
                secret_names: BTreeMap::new(),
                source_receipt_path: source_receipt,
            };
            let result = export_bundle(&spec)?;
            println!("manifest={}", result.manifest_path.display());
        }
        Commands::Export { command } => match command {
            ExportCommands::K8s {
                name,
                out_dir,
                entries,
            } => {
                let spec = ExportBundleSpec {
                    bundle_name: name,
                    out_dir,
                    target_format: ExportTargetFormat::KubernetesSecretYaml,
                    outputs: parse_entries(&entries)?,
                    env_var_names: BTreeMap::new(),
                    secret_names: BTreeMap::new(),
                    source_receipt_path: None,
                };
                let result = export_bundle(&spec)?;
                println!("manifest={}", result.manifest_path.display());
            }
            ExportCommands::VaultKvJson {
                name,
                out_dir,
                mount,
                path,
                entries,
            } => {
                let mut secret_names = BTreeMap::new();
                if let Some(mount) = mount {
                    secret_names.insert("vault_mount".to_string(), mount);
                }
                if let Some(path) = path {
                    secret_names.insert("vault_path".to_string(), path);
                }

                let spec = ExportBundleSpec {
                    bundle_name: name,
                    out_dir,
                    target_format: ExportTargetFormat::VaultKvJson,
                    outputs: parse_entries(&entries)?,
                    env_var_names: BTreeMap::new(),
                    secret_names,
                    source_receipt_path: None,
                };
                let result = export_bundle(&spec)?;
                println!("manifest={}", result.manifest_path.display());
            }
        },
    }

    Ok(())
}

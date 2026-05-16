use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "uselesskey", about = "Deterministic fixture generation CLI")]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Commands,
}

#[derive(Subcommand, Debug)]
pub(super) enum Commands {
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
pub(super) struct ProfilesArgs {
    #[arg(long)]
    pub(super) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(super) struct ProfileArgs {
    pub(super) profile: BundleProfile,
    #[arg(long)]
    pub(super) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(super) struct GenerateArgs {
    pub(super) kind: Kind,
    #[arg(long)]
    pub(super) seed: String,
    #[arg(long)]
    pub(super) label: String,
    #[arg(long)]
    pub(super) format: Format,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(super) struct BundleArgs {
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    pub(super) seed: String,
    #[arg(long, default_value = "bundle")]
    pub(super) label: String,
    #[arg(long, default_value = "jwk")]
    pub(super) format: Format,
    #[arg(long, default_value = "scanner-safe")]
    pub(super) profile: BundleProfile,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
    #[arg(long)]
    pub(super) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(super) struct VerifyBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(super) bundle_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub(super) struct InspectBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(super) bundle_dir: PathBuf,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(super) struct ExportArgs {
    #[command(subcommand)]
    pub(super) target: ExportTarget,
}

#[derive(Subcommand, Debug)]
pub(super) enum ExportTarget {
    K8s(ExportK8sArgs),
    VaultKvJson(ExportVaultKvJsonArgs),
}

#[derive(clap::Args, Debug)]
pub(super) struct ExportK8sArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(super) bundle_dir: PathBuf,
    #[arg(long)]
    pub(super) name: String,
    #[arg(long)]
    pub(super) namespace: Option<String>,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(super) struct ExportVaultKvJsonArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(super) bundle_dir: PathBuf,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(super) struct InspectArgs {
    #[arg(long)]
    pub(super) format: Format,
    #[arg(long)]
    pub(super) input: Option<PathBuf>,
    #[arg(long)]
    pub(super) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(super) struct MaterializeArgs {
    #[arg(long)]
    pub(super) manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub(super) out_dir: Option<PathBuf>,
    #[arg(long)]
    pub(super) emit_rs: Option<PathBuf>,
    #[arg(long, hide = true)]
    pub(super) check: bool,
}

#[derive(clap::Args, Debug)]
pub(super) struct VerifyArgs {
    #[arg(long)]
    pub(super) manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub(super) out_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum Kind {
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
    pub(super) const fn manifest_name(self) -> &'static str {
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
pub(super) enum Format {
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
    pub(super) const fn manifest_name(self) -> &'static str {
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
pub(super) enum BundleProfile {
    ScannerSafe,
    Oidc,
    Tls,
    Webhook,
    Runtime,
}

impl BundleProfile {
    pub(super) const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Tls => "tls",
            Self::Webhook => "webhook",
            Self::Runtime => "runtime",
        }
    }

    pub(super) const fn output_dir_hint(self) -> &'static str {
        match self {
            Self::ScannerSafe => "target/uselesskey-bundle",
            Self::Oidc => "target/uselesskey-oidc",
            Self::Tls => "target/uselesskey-tls",
            Self::Webhook => "target/uselesskey-webhook",
            Self::Runtime => "target/uselesskey-runtime",
        }
    }
}

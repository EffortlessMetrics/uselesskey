use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "uselesskey", about = "Deterministic fixture generation CLI")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
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
pub(crate) struct ProfilesArgs {
    #[arg(long)]
    pub(crate) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ProfileArgs {
    pub(crate) profile: BundleProfile,
    #[arg(long)]
    pub(crate) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct GenerateArgs {
    pub(crate) kind: Kind,
    #[arg(long)]
    pub(crate) seed: String,
    #[arg(long)]
    pub(crate) label: String,
    #[arg(long)]
    pub(crate) format: Format,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct BundleArgs {
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    pub(crate) seed: String,
    #[arg(long, default_value = "bundle")]
    pub(crate) label: String,
    #[arg(long, default_value = "jwk")]
    pub(crate) format: Format,
    #[arg(long, default_value = "scanner-safe")]
    pub(crate) profile: BundleProfile,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) explain: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(crate) bundle_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub(crate) struct InspectBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(crate) bundle_dir: PathBuf,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ExportArgs {
    #[command(subcommand)]
    pub(crate) target: ExportTarget,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ExportTarget {
    K8s(ExportK8sArgs),
    VaultKvJson(ExportVaultKvJsonArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct ExportK8sArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(crate) bundle_dir: PathBuf,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ExportVaultKvJsonArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub(crate) bundle_dir: PathBuf,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct InspectArgs {
    #[arg(long)]
    pub(crate) format: Format,
    #[arg(long)]
    pub(crate) input: Option<PathBuf>,
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct MaterializeArgs {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub(crate) out_dir: Option<PathBuf>,
    #[arg(long)]
    pub(crate) emit_rs: Option<PathBuf>,
    #[arg(long, hide = true)]
    pub(crate) check: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyArgs {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub(crate) out_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Kind {
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
    pub(crate) const fn manifest_name(self) -> &'static str {
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
pub(crate) enum Format {
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
    pub(crate) const fn manifest_name(self) -> &'static str {
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
pub(crate) enum BundleProfile {
    ScannerSafe,
    Oidc,
    Tls,
    Webhook,
    Runtime,
}

impl BundleProfile {
    pub(crate) const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Tls => "tls",
            Self::Webhook => "webhook",
            Self::Runtime => "runtime",
        }
    }

    pub(crate) const fn output_dir_hint(self) -> &'static str {
        match self {
            Self::ScannerSafe => "target/uselesskey-bundle",
            Self::Oidc => "target/uselesskey-oidc",
            Self::Tls => "target/uselesskey-tls",
            Self::Webhook => "target/uselesskey-webhook",
            Self::Runtime => "target/uselesskey-runtime",
        }
    }
}

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "uselesskey", about = "Deterministic fixture generation CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
pub struct ProfilesArgs {
    #[arg(long)]
    pub explain: bool,
}

#[derive(clap::Args, Debug)]
pub struct ProfileArgs {
    pub profile: BundleProfile,
    #[arg(long)]
    pub explain: bool,
}

#[derive(clap::Args, Debug)]
pub struct GenerateArgs {
    pub kind: Kind,
    #[arg(long)]
    pub seed: String,
    #[arg(long)]
    pub label: String,
    #[arg(long)]
    pub format: Format,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct BundleArgs {
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    pub seed: String,
    #[arg(long, default_value = "bundle")]
    pub label: String,
    #[arg(long, default_value = "jwk")]
    pub format: Format,
    #[arg(long, default_value = "scanner-safe")]
    pub profile: BundleProfile,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub explain: bool,
}

#[derive(clap::Args, Debug)]
pub struct VerifyBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub bundle_dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct InspectBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct ExportArgs {
    #[command(subcommand)]
    pub target: ExportTarget,
}

#[derive(Subcommand, Debug)]
pub enum ExportTarget {
    K8s(ExportK8sArgs),
    VaultKvJson(ExportVaultKvJsonArgs),
}

#[derive(clap::Args, Debug)]
pub struct ExportK8sArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub namespace: Option<String>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct ExportVaultKvJsonArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    pub bundle_dir: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct InspectArgs {
    #[arg(long)]
    pub format: Format,
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct MaterializeArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub out_dir: Option<PathBuf>,
    #[arg(long)]
    pub emit_rs: Option<PathBuf>,
    #[arg(long, hide = true)]
    pub check: bool,
}

#[derive(clap::Args, Debug)]
pub struct VerifyArgs {
    #[arg(long)]
    pub manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    pub out_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Kind {
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
    pub const fn manifest_name(self) -> &'static str {
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
pub enum Format {
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
    pub const fn manifest_name(self) -> &'static str {
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
pub enum BundleProfile {
    ScannerSafe,
    Oidc,
    Tls,
    Webhook,
    Runtime,
}

impl BundleProfile {
    pub const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Oidc => "oidc",
            Self::Tls => "tls",
            Self::Webhook => "webhook",
            Self::Runtime => "runtime",
        }
    }

    pub const fn output_dir_hint(self) -> &'static str {
        match self {
            Self::ScannerSafe => "target/uselesskey-bundle",
            Self::Oidc => "target/uselesskey-oidc",
            Self::Tls => "target/uselesskey-tls",
            Self::Webhook => "target/uselesskey-webhook",
            Self::Runtime => "target/uselesskey-runtime",
        }
    }
}

pub(crate) const DISCOVERABLE_PROFILES: [BundleProfile; 5] = [
    BundleProfile::ScannerSafe,
    BundleProfile::Tls,
    BundleProfile::Oidc,
    BundleProfile::Webhook,
    BundleProfile::Runtime,
];

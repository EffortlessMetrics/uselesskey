#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory,
    HmacFactoryExt, HmacSpec, RsaFactoryExt, RsaSpec, Seed, TokenFactoryExt, TokenSpec,
    X509FactoryExt, X509Spec,
};

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate deterministic test fixtures")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Generate(GenerateArgs),
    Bundle(BundleArgs),
    Inspect(InspectArgs),
}

#[derive(clap::Args, Debug)]
struct GenerateArgs {
    kind: ArtifactKind,
    #[arg(long)]
    seed: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    format: OutputFormat,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct BundleArgs {
    #[arg(long)]
    seed: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    format: OutputFormat,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct InspectArgs {
    #[arg(long)]
    seed: Option<String>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long)]
    format: OutputFormat,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    input: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactKind {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Jwk,
    Jwks,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
enum OutputFormat {
    Pem,
    Der,
    Jwk,
    Jwks,
    JsonManifest,
    FileBundleDirectory,
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    name: String,
    kind: ArtifactKind,
    format: OutputFormat,
    encoding: &'static str,
    path: Option<String>,
    bytes: usize,
}

#[derive(Debug, Serialize)]
struct BundleManifest {
    seed: String,
    label: String,
    generated_at: String,
    entries: Vec<ManifestEntry>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate(args) => cmd_generate(args),
        Command::Bundle(args) => cmd_bundle(args),
        Command::Inspect(args) => cmd_inspect(args),
    }
}

fn cmd_generate(args: GenerateArgs) -> Result<()> {
    let fx = build_factory(&args.seed)?;
    let bytes = generate_artifact(&fx, &args.label, args.kind, args.format)?;
    write_output(args.out.as_deref(), &bytes)
}

fn cmd_bundle(args: BundleArgs) -> Result<()> {
    let fx = build_factory(&args.seed)?;
    let mut entries = Vec::new();
    let mut files = Vec::new();

    let bundle_items = [
        ("rsa-private", ArtifactKind::Rsa, OutputFormat::Pem),
        ("ecdsa-private", ArtifactKind::Ecdsa, OutputFormat::Pem),
        ("ed25519-private", ArtifactKind::Ed25519, OutputFormat::Pem),
        ("hmac-jwk", ArtifactKind::Hmac, OutputFormat::Jwk),
        ("token", ArtifactKind::Token, OutputFormat::JsonManifest),
        ("x509-cert", ArtifactKind::X509, OutputFormat::Pem),
        ("rsa-jwks", ArtifactKind::Jwks, OutputFormat::Jwks),
    ];

    for (name, kind, format) in bundle_items {
        let bytes = generate_artifact(&fx, &format!("{}-{}", args.label, name), kind, format)?;
        entries.push(ManifestEntry {
            name: name.to_string(),
            kind,
            format,
            encoding: if std::str::from_utf8(&bytes).is_ok() {
                "utf8"
            } else {
                "base64"
            },
            path: Some(format!("{}.{}", name, file_extension(format))),
            bytes: bytes.len(),
        });
        files.push((format!("{}.{}", name, file_extension(format)), bytes));
    }

    let manifest = BundleManifest {
        seed: args.seed,
        label: args.label,
        generated_at: "deterministic".to_string(),
        entries,
    };

    match args.format {
        OutputFormat::JsonManifest => {
            let data = serde_json::to_vec_pretty(&manifest)?;
            write_output(args.out.as_deref(), &data)
        }
        OutputFormat::FileBundleDirectory => {
            let out_dir = args
                .out
                .as_deref()
                .context("--out is required for --format file-bundle-directory")?;
            fs::create_dir_all(out_dir)?;
            for (name, data) in files {
                fs::write(out_dir.join(name), data)?;
            }
            fs::write(
                out_dir.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
            Ok(())
        }
        other => bail!(
            "bundle only supports --format json-manifest or file-bundle-directory, got {other:?}"
        ),
    }
}

fn cmd_inspect(args: InspectArgs) -> Result<()> {
    let input = read_input(args.input.as_deref())?;
    let text = String::from_utf8_lossy(&input);
    let detected = detect_format(&text);
    let val = json!({
        "detected": detected,
        "length": input.len(),
        "seed": args.seed,
        "label": args.label,
    });

    let out = match args.format {
        OutputFormat::JsonManifest => serde_json::to_vec_pretty(&val)?,
        _ => serde_json::to_vec(&val)?,
    };

    write_output(args.out.as_deref(), &out)
}

fn build_factory(seed: &str) -> Result<Factory> {
    let seed = Seed::from_env_value(seed).map_err(anyhow::Error::msg).context("invalid --seed value")?;
    Ok(Factory::deterministic(seed))
}

fn generate_artifact(
    fx: &Factory,
    label: &str,
    kind: ArtifactKind,
    format: OutputFormat,
) -> Result<Vec<u8>> {
    let out = match (kind, format) {
        (ArtifactKind::Rsa, OutputFormat::Pem) => fx.rsa(label, RsaSpec::rs256()).private_key_pkcs8_pem().as_bytes().to_vec(),
        (ArtifactKind::Rsa, OutputFormat::Der) => fx.rsa(label, RsaSpec::rs256()).private_key_pkcs8_der().to_vec(),
        (ArtifactKind::Rsa, OutputFormat::Jwk) | (ArtifactKind::Jwk, OutputFormat::Jwk) => {
            serde_json::to_vec_pretty(&fx.rsa(label, RsaSpec::rs256()).public_jwk_json())?
        }
        (ArtifactKind::Jwks, OutputFormat::Jwks) | (ArtifactKind::Rsa, OutputFormat::Jwks) => {
            serde_json::to_vec_pretty(&fx.rsa(label, RsaSpec::rs256()).public_jwks_json())?
        }
        (ArtifactKind::Ecdsa, OutputFormat::Pem) => fx.ecdsa(label, EcdsaSpec::es256()).private_key_pkcs8_pem().as_bytes().to_vec(),
        (ArtifactKind::Ecdsa, OutputFormat::Der) => fx.ecdsa(label, EcdsaSpec::es256()).private_key_pkcs8_der().to_vec(),
        (ArtifactKind::Ecdsa, OutputFormat::Jwk) => {
            serde_json::to_vec_pretty(&fx.ecdsa(label, EcdsaSpec::es256()).public_jwk_json())?
        }
        (ArtifactKind::Ecdsa, OutputFormat::Jwks) => {
            serde_json::to_vec_pretty(&fx.ecdsa(label, EcdsaSpec::es256()).public_jwks_json())?
        }
        (ArtifactKind::Ed25519, OutputFormat::Pem) => fx.ed25519(label, Ed25519Spec::new()).private_key_pkcs8_pem().as_bytes().to_vec(),
        (ArtifactKind::Ed25519, OutputFormat::Der) => fx.ed25519(label, Ed25519Spec::new()).private_key_pkcs8_der().to_vec(),
        (ArtifactKind::Ed25519, OutputFormat::Jwk) => {
            serde_json::to_vec_pretty(&fx.ed25519(label, Ed25519Spec::new()).public_jwk_json())?
        }
        (ArtifactKind::Ed25519, OutputFormat::Jwks) => {
            serde_json::to_vec_pretty(&fx.ed25519(label, Ed25519Spec::new()).public_jwks_json())?
        }
        (ArtifactKind::Hmac, OutputFormat::Der) => fx.hmac(label, HmacSpec::hs256()).secret_bytes().to_vec(),
        (ArtifactKind::Hmac, OutputFormat::Jwk) => serde_json::to_vec_pretty(&fx.hmac(label, HmacSpec::hs256()).jwk().to_value())?,
        (ArtifactKind::Hmac, OutputFormat::Jwks) => serde_json::to_vec_pretty(&fx.hmac(label, HmacSpec::hs256()).jwks().to_value())?,
        (ArtifactKind::Token, OutputFormat::JsonManifest) => {
            let t = fx.token(label, TokenSpec::api_key());
            serde_json::to_vec_pretty(&json!({"token": t.value(), "authorization": t.authorization_header()}))?
        }
        (ArtifactKind::Token, OutputFormat::Pem) => fx.token(label, TokenSpec::api_key()).value().as_bytes().to_vec(),
        (ArtifactKind::X509, OutputFormat::Pem) => fx.x509_self_signed(label, X509Spec::self_signed(label)).cert_pem().as_bytes().to_vec(),
        (ArtifactKind::X509, OutputFormat::Der) => fx.x509_self_signed(label, X509Spec::self_signed(label)).cert_der().to_vec(),
        (ArtifactKind::X509, OutputFormat::JsonManifest) => {
            let cert = fx.x509_chain(label, ChainSpec::new(label));
            serde_json::to_vec_pretty(&json!({
                "leaf_subject": label,
                "leaf_pem": cert.leaf_cert_pem(),
                "chain_pem": cert.chain_pem(),
            }))?
        }
        (ArtifactKind::Jwk, OutputFormat::JsonManifest) => {
            serde_json::to_vec_pretty(&fx.rsa(label, RsaSpec::rs256()).public_jwk_json())?
        }
        (ArtifactKind::Jwks, OutputFormat::JsonManifest) => {
            serde_json::to_vec_pretty(&fx.rsa(label, RsaSpec::rs256()).public_jwks_json())?
        }
        _ => bail!("unsupported kind/format combination: {kind:?} + {format:?}"),
    };
    Ok(out)
}

fn write_output(out: Option<&Path>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = out {
        fs::write(path, bytes).with_context(|| format!("failed writing {}", path.display()))?;
    } else {
        io::stdout().write_all(bytes)?;
    }
    Ok(())
}

fn read_input(input: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(path) = input {
        return fs::read(path).with_context(|| format!("failed to read {}", path.display()));
    }
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn detect_format(s: &str) -> &'static str {
    if s.contains("BEGIN CERTIFICATE") || s.contains("BEGIN PRIVATE KEY") {
        "pem"
    } else if s.trim_start().starts_with('{') {
        "json"
    } else if STANDARD.decode(s.trim()).is_ok() {
        "base64"
    } else {
        "unknown"
    }
}

fn file_extension(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Pem => "pem",
        OutputFormat::Der => "der",
        OutputFormat::Jwk => "jwk.json",
        OutputFormat::Jwks => "jwks.json",
        OutputFormat::JsonManifest => "json",
        OutputFormat::FileBundleDirectory => "dir",
    }
}

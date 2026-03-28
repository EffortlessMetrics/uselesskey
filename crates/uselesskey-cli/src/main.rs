#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use uselesskey::{
    EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt, HmacSpec,
    RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
};

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
    Inspect(InspectArgs),
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
    #[arg(long)]
    seed: String,
    #[arg(long)]
    label: String,
    #[arg(long, default_value = "pem")]
    format: Format,
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
        Commands::Inspect(args) => run_inspect(args),
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
    for (name, kind) in [
        ("rsa", Kind::Rsa),
        ("ecdsa", Kind::Ecdsa),
        ("ed25519", Kind::Ed25519),
        ("hmac", Kind::Hmac),
        ("token", Kind::Token),
        ("x509", Kind::X509),
        ("jwk", Kind::Jwk),
        ("jwks", Kind::Jwks),
    ] {
        let bundle_format = preferred_bundle_format(kind, args.format);
        let artifact = generate_artifact(&fx, kind, &args.label, bundle_format)
            .with_context(|| format!("failed to generate {name}"))?;
        let ext = format_extension(bundle_format, &artifact);
        let file = out_dir.join(format!("{name}.{ext}"));
        write_artifact_to_path(&artifact, &file)?;
        files.push(file_name_string(&file)?);
    }

    let manifest = BundleManifest {
        version: 1,
        seed: args.seed,
        label: args.label,
        format: format!("{:?}", args.format).to_lowercase(),
        files,
    };
    let manifest_path = out_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    emit_artifact(&Artifact::Json(json!({"bundle_dir": out_dir, "manifest": manifest})), None)
}

fn preferred_bundle_format(kind: Kind, requested: Format) -> Format {
    match (kind, requested) {
        (Kind::Token, _) => Format::JsonManifest,
        (Kind::X509, Format::Jwk | Format::Jwks) => Format::Pem,
        (Kind::Hmac, Format::Pem) => Format::Der,
        (Kind::Jwk, _) => Format::Jwk,
        (Kind::Jwks, _) => Format::Jwks,
        _ => requested,
    }
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

fn write_artifact_to_path(artifact: &Artifact, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match artifact {
        Artifact::Text(t) => fs::write(path, t.as_bytes())?,
        Artifact::Binary(b) => fs::write(path, b)?,
        Artifact::Json(v) => fs::write(path, serde_json::to_vec_pretty(v)?)?,
    }
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

fn file_name_string(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|x| x.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("invalid file name: {}", path.display()))
}

fn detect_kind(text: &str) -> &'static str {
    if text.contains("BEGIN CERTIFICATE") {
        "x509"
    } else if text.contains("BEGIN PRIVATE KEY") {
        "private_key"
    } else if text.trim_start().starts_with("{") && text.contains("\"keys\"") {
        "jwks"
    } else if text.trim_start().starts_with("{") && text.contains("\"kty\"") {
        "jwk"
    } else {
        "unknown"
    }
}

#[derive(Debug, Serialize)]
struct BundleManifest {
    version: u32,
    seed: String,
    label: String,
    format: String,
    files: Vec<String>,
}

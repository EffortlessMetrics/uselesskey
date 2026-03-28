#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value};
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_jwk::JwksBuilder;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::TokenFactoryExt;
use uselesskey_token_spec::TokenSpec;
use uselesskey_x509::{X509FactoryExt, X509Spec};

#[derive(Parser, Debug)]
#[command(name = "uselesskey")]
#[command(about = "Deterministic fixture generation for non-Rust test stacks")]
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
    #[arg(value_enum)]
    kind: ArtifactKind,
    #[arg(long)]
    seed: String,
    #[arg(long)]
    label: String,
    #[arg(long, value_enum)]
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
    #[arg(long, value_enum)]
    format: BundleFormat,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long = "artifact", value_enum, required = true)]
    artifacts: Vec<ArtifactKind>,
}

#[derive(clap::Args, Debug)]
struct InspectArgs {
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long)]
    input: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Pem,
    Der,
    Jwk,
    Jwks,
    JsonManifest,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BundleFormat {
    JsonManifest,
    BundleDir,
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: &'a str,
    seed: &'a str,
    label: &'a str,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Serialize)]
struct ManifestArtifact {
    kind: ArtifactKind,
    format: String,
    bytes: usize,
    path: Option<String>,
    preview: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Generate(args) => handle_generate(args),
        Command::Bundle(args) => handle_bundle(args),
        Command::Inspect(args) => handle_inspect(args),
    }
}

fn handle_generate(args: GenerateArgs) -> Result<()> {
    let fx = deterministic_factory(&args.seed)?;
    let rendered = render_artifact(&fx, args.kind, &args.label, args.format)?;
    write_output(&rendered, args.out.as_deref())
}

fn handle_bundle(args: BundleArgs) -> Result<()> {
    let fx = deterministic_factory(&args.seed)?;
    let mut entries = Vec::new();

    match args.format {
        BundleFormat::JsonManifest => {
            for kind in args.artifacts {
                let bytes = render_artifact(&fx, kind, &args.label, OutputFormat::JsonManifest)?;
                let value: Value = serde_json::from_slice(&bytes).context("bundle json parse")?;
                entries.push(ManifestArtifact {
                    kind,
                    format: "json-manifest".to_string(),
                    bytes: bytes.len(),
                    path: None,
                    preview: compact_preview(&value),
                });
            }

            let manifest = Manifest {
                schema_version: "v1",
                seed: &args.seed,
                label: &args.label,
                artifacts: entries,
            };
            write_output(&serde_json::to_vec_pretty(&manifest)?, args.out.as_deref())
        }
        BundleFormat::BundleDir => {
            let out_dir = args
                .out
                .as_deref()
                .ok_or_else(|| anyhow!("--out is required for --format bundle-dir"))?;
            fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;

            for kind in args.artifacts {
                let (format, ext) = default_format_for_bundle(kind);
                let bytes = render_artifact(&fx, kind, &args.label, format)?;
                let file_name = format!("{}-{}.{}", args.label, kind_name(kind), ext);
                let path = out_dir.join(file_name);
                fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;

                entries.push(ManifestArtifact {
                    kind,
                    format: format_name(format).to_string(),
                    bytes: bytes.len(),
                    path: Some(path.display().to_string()),
                    preview: byte_preview(&bytes),
                });
            }

            let manifest = Manifest {
                schema_version: "v1",
                seed: &args.seed,
                label: &args.label,
                artifacts: entries,
            };
            let manifest_path = out_dir.join("manifest.json");
            fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
                .with_context(|| format!("write {}", manifest_path.display()))?;
            Ok(())
        }
    }
}

fn handle_inspect(args: InspectArgs) -> Result<()> {
    let mut input = Vec::new();
    if let Some(path) = args.input.as_deref() {
        input = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    } else {
        io::stdin().read_to_end(&mut input)?;
    }

    let parsed: Value = serde_json::from_slice(&input).context("inspect expects JSON input")?;
    let summary = json!({
        "kind": if parsed.get("schema_version").is_some() { "bundle_manifest" } else { "artifact" },
        "bytes": input.len(),
        "keys": parsed
            .as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default(),
    });
    write_output(&serde_json::to_vec_pretty(&summary)?, args.out.as_deref())
}

fn deterministic_factory(seed: &str) -> Result<Factory> {
    let parsed = Seed::from_env_value(seed).map_err(|_| anyhow!("invalid --seed value"))?;
    Ok(Factory::deterministic(parsed))
}

fn render_artifact(
    fx: &Factory,
    kind: ArtifactKind,
    label: &str,
    format: OutputFormat,
) -> Result<Vec<u8>> {
    match kind {
        ArtifactKind::Rsa => render_rsa(fx, label, format),
        ArtifactKind::Ecdsa => render_ecdsa(fx, label, format),
        ArtifactKind::Ed25519 => render_ed25519(fx, label, format),
        ArtifactKind::Hmac => render_hmac(fx, label, format),
        ArtifactKind::Token => render_token(fx, label, format),
        ArtifactKind::X509 => render_x509(fx, label, format),
        ArtifactKind::Jwk => render_jwk(fx, label, format),
        ArtifactKind::Jwks => render_jwks(fx, label, format),
    }
}

fn render_rsa(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let kp = fx.rsa(label, RsaSpec::rs256());
    match format {
        OutputFormat::Pem => Ok(kp.private_key_pkcs8_pem().as_bytes().to_vec()),
        OutputFormat::Der => Ok(kp.private_key_pkcs8_der().to_vec()),
        OutputFormat::Jwk => Ok(serde_json::to_vec_pretty(&kp.public_jwk_json())?),
        OutputFormat::Jwks => Ok(serde_json::to_vec_pretty(&kp.public_jwks_json())?),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::Rsa), "pkcs8-private", kp.private_key_pkcs8_der())
        }
    }
}

fn render_ecdsa(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let kp = fx.ecdsa(label, EcdsaSpec::es256());
    match format {
        OutputFormat::Pem => Ok(kp.private_key_pkcs8_pem().as_bytes().to_vec()),
        OutputFormat::Der => Ok(kp.private_key_pkcs8_der().to_vec()),
        OutputFormat::Jwk => Ok(serde_json::to_vec_pretty(&kp.public_jwk_json())?),
        OutputFormat::Jwks => Ok(serde_json::to_vec_pretty(&kp.public_jwks_json())?),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::Ecdsa), "pkcs8-private", kp.private_key_pkcs8_der())
        }
    }
}

fn render_ed25519(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let kp = fx.ed25519(label, Ed25519Spec::new());
    match format {
        OutputFormat::Pem => Ok(kp.private_key_pkcs8_pem().as_bytes().to_vec()),
        OutputFormat::Der => Ok(kp.private_key_pkcs8_der().to_vec()),
        OutputFormat::Jwk => Ok(serde_json::to_vec_pretty(&kp.public_jwk_json())?),
        OutputFormat::Jwks => Ok(serde_json::to_vec_pretty(&kp.public_jwks_json())?),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::Ed25519), "pkcs8-private", kp.private_key_pkcs8_der())
        }
    }
}

fn render_hmac(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let secret = fx.hmac(label, HmacSpec::hs256());
    match format {
        OutputFormat::Pem => bail!("hmac supports der/jwk/jwks/json-manifest, not pem"),
        OutputFormat::Der => Ok(secret.secret_bytes().to_vec()),
        OutputFormat::Jwk => Ok(serde_json::to_vec_pretty(&secret.jwk().to_value())?),
        OutputFormat::Jwks => Ok(serde_json::to_vec_pretty(&secret.jwks().to_value())?),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::Hmac), "raw-secret", secret.secret_bytes())
        }
    }
}

fn render_token(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let token = fx.token(label, TokenSpec::bearer());
    match format {
        OutputFormat::Pem | OutputFormat::Der => {
            bail!("token supports jwk/jwks/json-manifest output only")
        }
        OutputFormat::Jwk => Ok(serde_json::to_vec_pretty(&json!({
            "kty": "oct",
            "alg": "opaque",
            "kid": format!("token-{label}"),
            "value": token.value(),
        }))?),
        OutputFormat::Jwks => Ok(serde_json::to_vec_pretty(&json!({"keys": [{
            "kty": "oct",
            "alg": "opaque",
            "kid": format!("token-{label}"),
            "value": token.value(),
        }]}))?),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::Token), "token", token.value().as_bytes())
        }
    }
}

fn render_x509(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    let cert = fx.x509_self_signed(label, X509Spec::self_signed("example.test"));
    match format {
        OutputFormat::Pem => Ok(cert.identity_pem().as_bytes().to_vec()),
        OutputFormat::Der => Ok(cert.cert_der().to_vec()),
        OutputFormat::Jwk | OutputFormat::Jwks => bail!("x509 supports pem/der/json-manifest output only"),
        OutputFormat::JsonManifest => {
            artifact_manifest(kind_name(ArtifactKind::X509), "x509-cert", cert.cert_der())
        }
    }
}

fn render_jwk(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    if format != OutputFormat::Jwk && format != OutputFormat::JsonManifest {
        bail!("jwk artifact only supports jwk/json-manifest formats");
    }
    let rsa = fx.rsa(label, RsaSpec::rs256());
    let value = rsa.public_jwk_json();
    if format == OutputFormat::Jwk {
        Ok(serde_json::to_vec_pretty(&value)?)
    } else {
        artifact_manifest(
            kind_name(ArtifactKind::Jwk),
            "jwk",
            serde_json::to_string(&value)?.as_bytes(),
        )
    }
}

fn render_jwks(fx: &Factory, label: &str, format: OutputFormat) -> Result<Vec<u8>> {
    if format != OutputFormat::Jwks && format != OutputFormat::JsonManifest {
        bail!("jwks artifact only supports jwks/json-manifest formats");
    }
    let rsa = fx.rsa(label, RsaSpec::rs256());
    let ecdsa = fx.ecdsa(label, EcdsaSpec::es256());
    let mut builder = JwksBuilder::new();
    builder.push_public(rsa.public_jwk());
    builder.push_public(ecdsa.public_jwk());
    let jwks = builder.build().to_value();

    if format == OutputFormat::Jwks {
        Ok(serde_json::to_vec_pretty(&jwks)?)
    } else {
        artifact_manifest(
            kind_name(ArtifactKind::Jwks),
            "jwks",
            serde_json::to_string(&jwks)?.as_bytes(),
        )
    }
}

fn artifact_manifest(kind: &str, format: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&json!({
        "kind": kind,
        "format": format,
        "bytes": bytes.len(),
        "preview": byte_preview(bytes),
    }))?)
}

fn write_output(bytes: &[u8], out: Option<&Path>) -> Result<()> {
    match out {
        Some(path) => fs::write(path, bytes).with_context(|| format!("write {}", path.display())),
        None => {
            io::stdout().write_all(bytes)?;
            Ok(())
        }
    }
}

fn kind_name(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::Rsa => "rsa",
        ArtifactKind::Ecdsa => "ecdsa",
        ArtifactKind::Ed25519 => "ed25519",
        ArtifactKind::Hmac => "hmac",
        ArtifactKind::Token => "token",
        ArtifactKind::X509 => "x509",
        ArtifactKind::Jwk => "jwk",
        ArtifactKind::Jwks => "jwks",
    }
}

fn format_name(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Pem => "pem",
        OutputFormat::Der => "der",
        OutputFormat::Jwk => "jwk",
        OutputFormat::Jwks => "jwks",
        OutputFormat::JsonManifest => "json-manifest",
    }
}

fn default_format_for_bundle(kind: ArtifactKind) -> (OutputFormat, &'static str) {
    match kind {
        ArtifactKind::Rsa | ArtifactKind::Ecdsa | ArtifactKind::Ed25519 | ArtifactKind::X509 => {
            (OutputFormat::Pem, "pem")
        }
        ArtifactKind::Hmac => (OutputFormat::Der, "bin"),
        ArtifactKind::Token | ArtifactKind::Jwk => (OutputFormat::Jwk, "json"),
        ArtifactKind::Jwks => (OutputFormat::Jwks, "json"),
    }
}

fn byte_preview(bytes: &[u8]) -> String {
    let sample = &bytes[..bytes.len().min(16)];
    STANDARD.encode(sample)
}

fn compact_preview(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 80 {
        format!("{}...", &text[..80])
    } else {
        text
    }
}

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use blake3::Hasher;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use uselesskey::{
    ChainSpec, EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt,
    HmacSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate one fixture artifact.
    Generate {
        #[arg(value_enum)]
        kind: GenerateKind,
        #[arg(long)]
        seed: String,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        format: OutputFormat,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Emit multiple fixtures plus a machine-readable manifest.
    Bundle {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        format: BundleFormat,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Inspect deterministic fixture metadata without writing files.
    Inspect {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        format: OutputFormat,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum GenerateKind {
    Rsa,
    Ecdsa,
    Ed25519,
    Hmac,
    Token,
    X509,
    Jwk,
    Jwks,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Pem,
    Der,
    Jwk,
    Jwks,
    JsonManifest,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum BundleFormat {
    JsonManifest,
    BundleDir,
}

#[derive(Debug)]
enum ArtifactData {
    Text(String),
    Binary(Vec<u8>),
    Json(serde_json::Value),
}

#[derive(Debug, Serialize)]
struct Manifest {
    schema_version: u32,
    seed_source: String,
    label: String,
    artifact_kind: String,
    format: String,
    bytes: usize,
    digest_blake3_hex: String,
}

#[derive(Debug, Serialize)]
struct BundleManifest {
    schema_version: u32,
    seed_source: String,
    label: String,
    files: Vec<BundleFile>,
}

#[derive(Debug, Serialize)]
struct BundleFile {
    name: String,
    bytes: usize,
    digest_blake3_hex: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate {
            kind,
            seed,
            label,
            format,
            out,
        } => {
            let (seed, label) = resolve_seed_label(seed, label)?;
            let artifact = generate_one(kind, &seed, &label, format)?;
            write_output(artifact, out)
        }
        Commands::Bundle {
            seed,
            label,
            format,
            out,
        } => {
            let (seed, label) = resolve_seed_label(seed, label)?;
            run_bundle(&seed, &label, format, out)
        }
        Commands::Inspect {
            seed,
            label,
            format,
            out,
        } => {
            let (seed, label) = resolve_seed_label(seed, label)?;
            let inspect = json!({
                "schema_version": 1,
                "seed_source": seed,
                "label": label,
                "requested_format": format_name(format),
                "supported_generate_kinds": ["rsa", "ecdsa", "ed25519", "hmac", "token", "x509", "jwk", "jwks"],
            });
            write_output(ArtifactData::Json(inspect), out)
        }
    }
}

fn resolve_seed_label(seed: String, label: String) -> Result<(String, String), String> {
    if seed == "-" && label == "-" {
        return Err("--seed and --label cannot both read from stdin".to_string());
    }
    let stdin_value = if seed == "-" || label == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        buf.trim().to_string()
    } else {
        String::new()
    };

    let seed = if seed == "-" { stdin_value.clone() } else { seed };
    let label = if label == "-" { stdin_value } else { label };

    if seed.is_empty() {
        return Err("--seed must not be empty".to_string());
    }
    if label.is_empty() {
        return Err("--label must not be empty".to_string());
    }

    Ok((seed, label))
}

fn generate_one(
    kind: GenerateKind,
    seed: &str,
    label: &str,
    format: OutputFormat,
) -> Result<ArtifactData, String> {
    let fx = Factory::deterministic_from_str(seed);

    let output = match kind {
        GenerateKind::Rsa => match format {
            OutputFormat::Pem => ArtifactData::Text(fx.rsa(label, RsaSpec::rs256()).private_key_pkcs8_pem().to_string()),
            OutputFormat::Der => ArtifactData::Binary(fx.rsa(label, RsaSpec::rs256()).private_key_pkcs8_der().to_vec()),
            OutputFormat::Jwk => ArtifactData::Json(fx.rsa(label, RsaSpec::rs256()).public_jwk_json()),
            OutputFormat::Jwks => ArtifactData::Json(fx.rsa(label, RsaSpec::rs256()).public_jwks_json()),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
        },
        GenerateKind::Ecdsa => match format {
            OutputFormat::Pem => ArtifactData::Text(fx.ecdsa(label, EcdsaSpec::es256()).private_key_pkcs8_pem().to_string()),
            OutputFormat::Der => ArtifactData::Binary(fx.ecdsa(label, EcdsaSpec::es256()).private_key_pkcs8_der().to_vec()),
            OutputFormat::Jwk => ArtifactData::Json(fx.ecdsa(label, EcdsaSpec::es256()).public_jwk_json()),
            OutputFormat::Jwks => ArtifactData::Json(fx.ecdsa(label, EcdsaSpec::es256()).public_jwks_json()),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
        },
        GenerateKind::Ed25519 => match format {
            OutputFormat::Pem => ArtifactData::Text(fx.ed25519(label, Ed25519Spec::new()).private_key_pkcs8_pem().to_string()),
            OutputFormat::Der => ArtifactData::Binary(fx.ed25519(label, Ed25519Spec::new()).private_key_pkcs8_der().to_vec()),
            OutputFormat::Jwk => ArtifactData::Json(fx.ed25519(label, Ed25519Spec::new()).public_jwk_json()),
            OutputFormat::Jwks => ArtifactData::Json(fx.ed25519(label, Ed25519Spec::new()).public_jwks_json()),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
        },
        GenerateKind::Hmac => match format {
            OutputFormat::Der => ArtifactData::Binary(fx.hmac(label, HmacSpec::hs256()).secret_bytes().to_vec()),
            OutputFormat::Jwk => ArtifactData::Json(fx.hmac(label, HmacSpec::hs256()).jwk().to_value()),
            OutputFormat::Jwks => ArtifactData::Json(fx.hmac(label, HmacSpec::hs256()).jwks().to_value()),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
            _ => return Err(format!("format '{}' not supported for hmac", format_name(format))),
        },
        GenerateKind::Token => match format {
            OutputFormat::Pem => ArtifactData::Text(fx.token(label, TokenSpec::api_key()).value().to_string()),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
            _ => return Err(format!("format '{}' not supported for token", format_name(format))),
        },
        GenerateKind::X509 => match format {
            OutputFormat::Pem => ArtifactData::Text(
                fx.x509_self_signed(label, uselesskey::X509Spec::self_signed("localhost"))
                    .identity_pem(),
            ),
            OutputFormat::Der => ArtifactData::Binary(
                fx.x509_self_signed(label, uselesskey::X509Spec::self_signed("localhost"))
                    .cert_der()
                    .to_vec(),
            ),
            OutputFormat::JsonManifest => return manifest_for(kind, format, seed, label),
            _ => return Err(format!("format '{}' not supported for x509", format_name(format))),
        },
        GenerateKind::Jwk => {
            if format != OutputFormat::Jwk {
                return Err("generate jwk requires --format jwk".to_string());
            }
            ArtifactData::Json(fx.rsa(label, RsaSpec::rs256()).public_jwk_json())
        }
        GenerateKind::Jwks => {
            if format != OutputFormat::Jwks {
                return Err("generate jwks requires --format jwks".to_string());
            }
            ArtifactData::Json(fx.rsa(label, RsaSpec::rs256()).public_jwks_json())
        }
    };

    Ok(output)
}

fn manifest_for(
    kind: GenerateKind,
    format: OutputFormat,
    seed: &str,
    label: &str,
) -> Result<ArtifactData, String> {
    let data = generate_one(kind, seed, label, OutputFormat::Pem).or_else(|_| {
        generate_one(kind, seed, label, OutputFormat::Der).or_else(|_| {
            generate_one(kind, seed, label, OutputFormat::Jwk)
                .or_else(|_| generate_one(kind, seed, label, OutputFormat::Jwks))
        })
    })?;
    let bytes = as_bytes(&data)?;
    let manifest = Manifest {
        schema_version: 1,
        seed_source: seed.to_string(),
        label: label.to_string(),
        artifact_kind: kind_name(kind).to_string(),
        format: format_name(format).to_string(),
        bytes: bytes.len(),
        digest_blake3_hex: digest_hex(&bytes),
    };
    Ok(ArtifactData::Json(
        serde_json::to_value(manifest).map_err(|e| e.to_string())?,
    ))
}

fn run_bundle(
    seed: &str,
    label: &str,
    format: BundleFormat,
    out: Option<PathBuf>,
) -> Result<(), String> {
    let fx = Factory::deterministic_from_str(seed);
    let rsa = fx.rsa(label, RsaSpec::rs256());
    let ecdsa = fx.ecdsa(label, EcdsaSpec::es256());
    let ed25519 = fx.ed25519(label, Ed25519Spec::new());
    let hmac = fx.hmac(label, HmacSpec::hs256());
    let token = fx.token(label, TokenSpec::api_key());
    let x509 = fx.x509_chain(label, ChainSpec::new("localhost"));

    let entries: Vec<(&str, ArtifactData)> = vec![
        ("rsa-private.pem", ArtifactData::Text(rsa.private_key_pkcs8_pem().to_string())),
        ("ecdsa-private.pem", ArtifactData::Text(ecdsa.private_key_pkcs8_pem().to_string())),
        ("ed25519-private.pem", ArtifactData::Text(ed25519.private_key_pkcs8_pem().to_string())),
        ("hmac.key", ArtifactData::Binary(hmac.secret_bytes().to_vec())),
        ("token.txt", ArtifactData::Text(token.value().to_string())),
        ("x509-chain.pem", ArtifactData::Text(x509.chain_pem().to_string())),
        ("jwks.json", ArtifactData::Json(rsa.public_jwks_json())),
    ];

    let mut files = Vec::new();

    match format {
        BundleFormat::JsonManifest => {
            for (name, data) in &entries {
                let bytes = as_bytes(data)?;
                files.push(BundleFile {
                    name: (*name).to_string(),
                    bytes: bytes.len(),
                    digest_blake3_hex: digest_hex(&bytes),
                });
            }
            let manifest = BundleManifest {
                schema_version: 1,
                seed_source: seed.to_string(),
                label: label.to_string(),
                files,
            };
            write_output(
                ArtifactData::Json(serde_json::to_value(manifest).map_err(|e| e.to_string())?),
                out,
            )
        }
        BundleFormat::BundleDir => {
            let target_dir = out.ok_or_else(|| "bundle-dir requires --out <directory>".to_string())?;
            fs::create_dir_all(&target_dir).map_err(|e| e.to_string())?;
            for (name, data) in &entries {
                let bytes = as_bytes(data)?;
                let path = target_dir.join(name);
                fs::write(&path, &bytes).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
                files.push(BundleFile {
                    name: (*name).to_string(),
                    bytes: bytes.len(),
                    digest_blake3_hex: digest_hex(&bytes),
                });
            }
            let manifest = BundleManifest {
                schema_version: 1,
                seed_source: seed.to_string(),
                label: label.to_string(),
                files,
            };
            let manifest_path = target_dir.join("manifest.json");
            fs::write(
                &manifest_path,
                serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("failed to write {}: {e}", manifest_path.display()))
        }
    }
}

fn write_output(data: ArtifactData, out: Option<PathBuf>) -> Result<(), String> {
    let bytes = as_bytes(&data)?;
    match out {
        Some(path) => fs::write(path, bytes).map_err(|e| e.to_string()),
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&bytes).map_err(|e| e.to_string())
        }
    }
}

fn as_bytes(data: &ArtifactData) -> Result<Vec<u8>, String> {
    match data {
        ArtifactData::Text(s) => Ok(s.as_bytes().to_vec()),
        ArtifactData::Binary(v) => Ok(v.clone()),
        ArtifactData::Json(v) => serde_json::to_vec_pretty(v).map_err(|e| e.to_string()),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn kind_name(kind: GenerateKind) -> &'static str {
    match kind {
        GenerateKind::Rsa => "rsa",
        GenerateKind::Ecdsa => "ecdsa",
        GenerateKind::Ed25519 => "ed25519",
        GenerateKind::Hmac => "hmac",
        GenerateKind::Token => "token",
        GenerateKind::X509 => "x509",
        GenerateKind::Jwk => "jwk",
        GenerateKind::Jwks => "jwks",
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


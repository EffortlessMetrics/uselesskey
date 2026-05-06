#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uselesskey_cli::{
    emit_include_bytes_module, load_materialize_manifest, materialize_manifest_to_dir,
};
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};
use uselesskey_x509::{X509FactoryExt, X509Spec};

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
    VerifyBundle(VerifyBundleArgs),
    Inspect(InspectArgs),
    Materialize(MaterializeArgs),
    Verify(VerifyArgs),
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
    #[arg(long, default_value = "uselesskey-bundle-seed")]
    seed: String,
    #[arg(long, default_value = "bundle")]
    label: String,
    #[arg(long, default_value = "jwk")]
    format: Format,
    #[arg(long, default_value = "scanner-safe")]
    profile: BundleProfile,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct VerifyBundleArgs {
    #[arg(long = "bundle-dir", alias = "path")]
    bundle_dir: PathBuf,
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

#[derive(clap::Args, Debug)]
struct MaterializeArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    out_dir: Option<PathBuf>,
    #[arg(long)]
    emit_rs: Option<PathBuf>,
    #[arg(long, hide = true)]
    check: bool,
}

#[derive(clap::Args, Debug)]
struct VerifyArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "out-dir", alias = "out")]
    out_dir: Option<PathBuf>,
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

impl Kind {
    const fn manifest_name(self) -> &'static str {
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

impl Format {
    const fn manifest_name(self) -> &'static str {
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
enum BundleProfile {
    ScannerSafe,
    Runtime,
}

impl BundleProfile {
    const fn manifest_name(self) -> &'static str {
        match self {
            Self::ScannerSafe => "scanner-safe",
            Self::Runtime => "runtime",
        }
    }
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
        Commands::VerifyBundle(args) => run_verify_bundle(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Materialize(args) => run_materialize(args),
        Commands::Verify(args) => run_verify(args),
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
    let mut artifacts = Vec::new();
    for (name, kind) in bundle_entries() {
        let bundle_format = preferred_bundle_format(kind, args.format, args.profile);
        let artifact =
            generate_bundle_artifact(&fx, kind, name, &args.label, bundle_format, args.profile)
                .with_context(|| format!("failed to generate {name}"))?;
        let ext = format_extension(bundle_format, &artifact);
        let file_name = format!("{name}.{ext}");
        let file = out_dir.join(&file_name);
        write_artifact_to_path(&artifact, &file)?;
        files.push(file_name.clone());
        artifacts.push(bundle_artifact_record(
            kind,
            bundle_format,
            &file_name,
            args.profile,
        ));
    }

    let manifest = BundleManifest {
        version: 1,
        profile: args.profile.manifest_name().to_string(),
        seed: args.seed,
        label: args.label,
        format: args.format.manifest_name().to_string(),
        files,
        artifacts,
    };
    let manifest_path = out_dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    emit_artifact(
        &Artifact::Json(json!({"bundle_dir": out_dir, "manifest": manifest})),
        None,
    )
}

fn run_verify_bundle(args: VerifyBundleArgs) -> Result<()> {
    let manifest_path = args.bundle_dir.join("manifest.json");
    let manifest = load_bundle_manifest(&manifest_path)
        .with_context(|| format!("invalid bundle manifest {}", manifest_path.display()))?;
    let files = verify_bundle_manifest(&args.bundle_dir, &manifest)
        .with_context(|| format!("failed to verify bundle {}", args.bundle_dir.display()))?;

    emit_artifact(
        &Artifact::Json(json!({
            "verify_bundle": {
                "status": "ok",
                "bundle_dir": args.bundle_dir,
                "manifest": manifest_path,
                "count": files.len(),
                "files": files,
            }
        })),
        None,
    )
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

fn run_materialize(args: MaterializeArgs) -> Result<()> {
    let manifest = load_materialize_manifest(&args.manifest)
        .with_context(|| format!("invalid materialize manifest {}", args.manifest.display()))?;
    let out_dir = args
        .out_dir
        .unwrap_or_else(|| PathBuf::from("target/uselesskey-fixtures"));
    let summary = materialize_manifest_to_dir(&manifest, &out_dir, args.check)
        .with_context(|| format!("failed to materialize {}", args.manifest.display()))?;

    if let Some(module_path) = args.emit_rs.as_deref() {
        emit_include_bytes_module(&manifest, &out_dir, module_path).with_context(|| {
            format!(
                "failed to emit include_bytes module {}",
                module_path.display()
            )
        })?;
    }

    let status = if args.check { "ok" } else { "written" };
    emit_artifact(
        &Artifact::Json(json!({
            "materialize": {
                "status": status,
                "out": out_dir,
                "count": summary.count,
                "files": summary.files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                "check": args.check,
                "emit_rs": args.emit_rs,
            }
        })),
        None,
    )
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let manifest = load_materialize_manifest(&args.manifest)
        .with_context(|| format!("invalid materialize manifest {}", args.manifest.display()))?;
    let out_dir = args
        .out_dir
        .unwrap_or_else(|| PathBuf::from("target/uselesskey-fixtures"));
    let summary = materialize_manifest_to_dir(&manifest, &out_dir, true)
        .with_context(|| format!("failed to verify {}", args.manifest.display()))?;

    emit_artifact(
        &Artifact::Json(json!({
            "verify": {
                "status": "ok",
                "out": out_dir,
                "count": summary.count,
                "files": summary.files.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            }
        })),
        None,
    )
}

fn load_bundle_manifest(path: &Path) -> Result<BundleManifest> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: BundleManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if manifest.version != 1 {
        bail!("unsupported bundle manifest version {}", manifest.version);
    }
    Ok(manifest)
}

fn verify_bundle_manifest(bundle_dir: &Path, manifest: &BundleManifest) -> Result<Vec<String>> {
    let format = parse_manifest_format(&manifest.format)?;
    let profile = parse_manifest_profile(&manifest.profile)?;
    let fx = Factory::deterministic_from_str(&manifest.seed);
    let mut expected_files = Vec::new();
    let mut expected_artifacts = Vec::new();

    for (name, kind) in bundle_entries() {
        let bundle_format = preferred_bundle_format(kind, format, profile);
        let artifact =
            generate_bundle_artifact(&fx, kind, name, &manifest.label, bundle_format, profile)
                .with_context(|| format!("failed to regenerate {name}"))?;
        let ext = format_extension(bundle_format, &artifact);
        let file_name = format!("{name}.{ext}");
        let expected = artifact_bytes(&artifact)?;
        let path = bundle_dir.join(&file_name);
        let actual =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        if actual != expected {
            bail!(
                "bundle verification failed: {} content mismatch",
                path.display()
            );
        }
        expected_files.push(file_name);
        expected_artifacts.push(bundle_artifact_record(
            kind,
            bundle_format,
            expected_files.last().expect("just pushed"),
            profile,
        ));
    }

    if manifest.files != expected_files {
        bail!(
            "bundle verification failed: manifest file list mismatch; expected {:?}, found {:?}",
            expected_files,
            manifest.files
        );
    }

    if !manifest.artifacts.is_empty() && manifest.artifacts != expected_artifacts {
        bail!(
            "bundle verification failed: artifact metadata mismatch; expected {:?}, found {:?}",
            expected_artifacts,
            manifest.artifacts
        );
    }

    Ok(expected_files)
}

fn parse_manifest_format(raw: &str) -> Result<Format> {
    match raw {
        "pem" => Ok(Format::Pem),
        "der" => Ok(Format::Der),
        "jwk" => Ok(Format::Jwk),
        "jwks" => Ok(Format::Jwks),
        "json-manifest" | "jsonmanifest" => Ok(Format::JsonManifest),
        "bundle-dir" | "bundledir" => Ok(Format::BundleDir),
        other => bail!("unsupported bundle manifest format `{other}`"),
    }
}

fn parse_manifest_profile(raw: &str) -> Result<BundleProfile> {
    match raw {
        "scanner-safe" | "scannersafe" => Ok(BundleProfile::ScannerSafe),
        "runtime" => Ok(BundleProfile::Runtime),
        other => bail!("unsupported bundle manifest profile `{other}`"),
    }
}

fn bundle_entries() -> [(&'static str, Kind); 8] {
    [
        ("rsa", Kind::Rsa),
        ("ecdsa", Kind::Ecdsa),
        ("ed25519", Kind::Ed25519),
        ("hmac", Kind::Hmac),
        ("token", Kind::Token),
        ("x509", Kind::X509),
        ("jwk", Kind::Jwk),
        ("jwks", Kind::Jwks),
    ]
}

fn bundle_artifact_record(
    kind: Kind,
    format: Format,
    path: &str,
    profile: BundleProfile,
) -> BundleArtifactRecord {
    BundleArtifactRecord {
        path: path.to_string(),
        kind: kind.manifest_name().to_string(),
        format: format.manifest_name().to_string(),
        profile: profile.manifest_name().to_string(),
        lanes: vec!["runtime".to_string(), "materialized".to_string()],
        scanner_safe: bundle_artifact_is_scanner_safe(kind, profile),
        description: bundle_artifact_description(kind, profile).to_string(),
    }
}

fn bundle_artifact_is_scanner_safe(kind: Kind, profile: BundleProfile) -> bool {
    match profile {
        BundleProfile::ScannerSafe => true,
        BundleProfile::Runtime => matches!(kind, Kind::Jwk | Kind::Jwks | Kind::X509),
    }
}

fn bundle_artifact_description(kind: Kind, profile: BundleProfile) -> &'static str {
    match (profile, kind) {
        (BundleProfile::ScannerSafe, Kind::Hmac) => {
            "scanner-safe symmetric JWK shape with invalid material"
        }
        (BundleProfile::ScannerSafe, Kind::Token) => {
            "scanner-safe near-miss token shape for parser tests"
        }
        (BundleProfile::ScannerSafe, Kind::X509) => "public certificate fixture",
        (BundleProfile::ScannerSafe, _) => "public fixture material",
        (BundleProfile::Runtime, Kind::Jwk | Kind::Jwks | Kind::X509) => {
            "runtime-generated public fixture material"
        }
        (BundleProfile::Runtime, _) => "runtime-generated fixture material",
    }
}

fn preferred_bundle_format(kind: Kind, requested: Format, profile: BundleProfile) -> Format {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return match kind {
            Kind::Token => Format::JsonManifest,
            Kind::X509 => Format::Pem,
            Kind::Jwks => Format::Jwks,
            Kind::Rsa | Kind::Ecdsa | Kind::Ed25519 | Kind::Hmac | Kind::Jwk => Format::Jwk,
        };
    }

    match (kind, requested) {
        (Kind::Token, _) => Format::JsonManifest,
        (Kind::X509, Format::Jwk | Format::Jwks) => Format::Pem,
        (Kind::Hmac, Format::Pem) => Format::Der,
        (Kind::Jwk, _) => Format::Jwk,
        (Kind::Jwks, _) => Format::Jwks,
        _ => requested,
    }
}

fn generate_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
    profile: BundleProfile,
) -> Result<Artifact> {
    if matches!(profile, BundleProfile::ScannerSafe) {
        return generate_scanner_safe_bundle_artifact(fx, kind, name, label, format);
    }

    generate_artifact(fx, kind, label, format)
}

fn generate_scanner_safe_bundle_artifact(
    fx: &Factory,
    kind: Kind,
    name: &str,
    label: &str,
    format: Format,
) -> Result<Artifact> {
    match kind {
        Kind::Hmac => {
            if matches!(format, Format::Jwk) {
                Ok(Artifact::Json(json!({
                    "kty": "oct",
                    "use": "sig",
                    "alg": "HS256",
                    "kid": format!("{label}-{name}"),
                    "k": "not_base64url!*",
                })))
            } else {
                unsupported(kind, format)
            }
        }
        Kind::Token => {
            let token = fx.token(label, TokenSpec::api_key());
            if matches!(format, Format::JsonManifest) {
                Ok(Artifact::Json(json!({
                    "kind": "token",
                    "label": label,
                    "negative": NegativeToken::NearMissApiKey.variant_name(),
                    "value": token.negative_value(NegativeToken::NearMissApiKey),
                })))
            } else {
                unsupported(kind, format)
            }
        }
        _ => generate_artifact(fx, kind, label, format),
    }
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

fn artifact_bytes(artifact: &Artifact) -> Result<Vec<u8>> {
    match artifact {
        Artifact::Text(t) => Ok(t.as_bytes().to_vec()),
        Artifact::Binary(b) => Ok(b.clone()),
        Artifact::Json(v) => Ok(serde_json::to_vec_pretty(v)?),
    }
}

fn write_artifact_to_path(artifact: &Artifact, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, artifact_bytes(artifact)?)?;
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

fn detect_kind(text: &str) -> &'static str {
    if text.contains("BEGIN CERTIFICATE") {
        "x509"
    } else if text.contains("BEGIN PRIVATE KEY") {
        "private_key"
    } else {
        detect_json_kind(text).unwrap_or("unknown")
    }
}

fn detect_json_kind(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }

    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let object = value.as_object()?;
    if object
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .is_some()
    {
        Some("jwks")
    } else if object
        .get("kty")
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        Some("jwk")
    } else {
        None
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct BundleManifest {
    version: u32,
    #[serde(default = "default_bundle_profile")]
    profile: String,
    seed: String,
    label: String,
    format: String,
    files: Vec<String>,
    #[serde(default)]
    artifacts: Vec<BundleArtifactRecord>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BundleArtifactRecord {
    path: String,
    kind: String,
    format: String,
    profile: String,
    lanes: Vec<String>,
    scanner_safe: bool,
    description: String,
}

fn default_bundle_profile() -> String {
    "runtime".to_string()
}

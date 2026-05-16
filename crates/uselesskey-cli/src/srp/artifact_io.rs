use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};

use super::Format;

#[derive(Debug)]
pub(super) enum Artifact {
    Text(String),
    Binary(Vec<u8>),
    Json(serde_json::Value),
}

pub(super) fn emit_artifact(artifact: &Artifact, out: Option<&Path>) -> Result<()> {
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

pub(super) fn artifact_bytes(artifact: &Artifact) -> Result<Vec<u8>> {
    match artifact {
        Artifact::Text(t) => Ok(t.as_bytes().to_vec()),
        Artifact::Binary(b) => Ok(b.clone()),
        Artifact::Json(v) => Ok(serde_json::to_vec_pretty(v)?),
    }
}

pub(super) fn write_artifact_to_path(artifact: &Artifact, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, artifact_bytes(artifact)?)?;
    Ok(())
}

pub(super) fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
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

pub(super) fn format_extension(format: Format, artifact: &Artifact) -> &'static str {
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

pub(super) fn detect_kind(text: &str) -> &'static str {
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

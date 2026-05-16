use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

use super::classify::{classify_by_content, classify_by_extension};

pub(crate) struct BlobHit {
    pub(crate) rel_path: String,
    pub(crate) kind: &'static str,
    pub(crate) suggestion: &'static str,
}

/// Scan for blobs and emit migration recipes (read-only).
pub(crate) fn migrate() -> Result<()> {
    let offenders = find_secret_blobs()?;
    if offenders.is_empty() {
        println!("no-blob: no secret-shaped fixtures found");
        return Ok(());
    }

    println!(
        "no-blob migrate: found {} secret-shaped fixture(s)",
        offenders.len()
    );
    println!();
    println!("# Migration Recipe");
    println!();
    for (i, hit) in offenders.iter().enumerate() {
        println!("## {}. {}", i + 1, hit.rel_path);
        println!();
        println!("  Detected: {}", hit.kind);
        println!();
        println!("  Suggested replacement:");
        println!("  ```rust");
        println!("  {}", hit.suggestion);
        println!("  ```");
        println!();
        println!("---\n");
    }

    println!("# Next Steps");
    println!();
    println!("1. Identify the fixture type (see suggested replacement above)");
    println!("2. Replace static file with runtime generation using uselesskey");
    println!(
        "3. Remove the static file: `git rm {}`",
        offenders
            .iter()
            .map(|h| h.rel_path.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("4. Re-run `cargo xtask no-blob` to verify");
    println!();
    println!("For more details, see: https://docs.rs/uselesskey");

    Ok(())
}

pub(crate) fn find_secret_blobs() -> Result<Vec<BlobHit>> {
    let mut offenders = Vec::new();
    let root = Path::new(".");
    walk_for_blobs(root, root, &mut offenders)?;
    Ok(offenders)
}

pub(crate) fn walk_for_blobs(root: &Path, dir: &Path, offenders: &mut Vec<BlobHit>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir failed for {dir:?}"))? {
        let entry = entry.context("failed to read dir entry")?;
        let path = entry.path();
        if path.is_dir() {
            if is_ignored_dir(&path) {
                continue;
            }
            walk_for_blobs(root, &path, offenders)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !should_scan_path(&rel_str) {
                continue;
            }
            if let Some((kind, suggestion)) = detect_and_classify(&path)? {
                offenders.push(BlobHit {
                    rel_path: rel_str,
                    kind,
                    suggestion,
                });
            }
        }
    }
    Ok(())
}

/// Read the file header once and use it for both detection and classification.
/// Returns `Some((kind, suggestion))` if the file is a secret-shaped blob.
fn detect_and_classify(path: &Path) -> Result<Option<(&'static str, &'static str)>> {
    let ext_hit = is_secret_extension(path);
    let header = read_file_header(path)?;
    let allow_secret_markers = !is_source_like_extension(path);

    if let Some(hit) = classify_by_content(&header, allow_secret_markers) {
        return Ok(Some(hit));
    }

    if ext_hit {
        return Ok(Some(classify_by_extension(path)));
    }

    if allow_secret_markers && has_secret_markers(&header) {
        return Ok(Some(classify_by_extension(path)));
    }

    Ok(None)
}

/// Read a bounded prefix of a file for marker detection.
fn read_file_header(path: &Path) -> Result<Vec<u8>> {
    const HEADER_SIZE: u64 = 64 * 1024;
    let file = fs::File::open(path).with_context(|| format!("failed to read {path:?}"))?;
    let mut buf = Vec::new();
    file.take(HEADER_SIZE).read_to_end(&mut buf)?;
    Ok(buf)
}

fn is_source_like_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(ext.as_str(), "rs" | "feature" | "md" | "toml" | "snap")
}

/// Check if a file header contains PEM, SSH, or other secret markers.
fn has_secret_markers(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("-----BEGIN") && text.contains("-----END") {
        return true;
    }
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ssh-rsa ")
            || trimmed.starts_with("ssh-ed25519 ")
            || trimmed.starts_with("ssh-dss ")
            || trimmed.starts_with("ecdsa-sha2-")
        {
            return true;
        }
    }
    false
}

fn is_ignored_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(name, ".git" | "target" | ".cargo")
}

pub(crate) fn should_scan_path(path: &str) -> bool {
    path.starts_with("tests/")
        || path.starts_with("fixtures/")
        || path.starts_with("testdata/")
        || (path.starts_with("crates/") && path.contains("/tests/"))
}

pub(crate) fn is_secret_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        ext.as_str(),
        "pem" | "der" | "key" | "crt" | "cer" | "p12" | "pfx" | "pub"
    ) {
        return true;
    }
    // SSH private key filenames: id_rsa, id_ed25519, id_ecdsa (no extension)
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(stem.as_str(), "id_rsa" | "id_ed25519" | "id_ecdsa")
}

/// Backward-compatible wrapper used by tests. Delegates to `read_file_header` + `has_secret_markers`.
#[cfg(test)]
pub(crate) fn contains_pem_markers(path: &Path) -> Result<bool> {
    if is_source_like_extension(path) {
        return Ok(false);
    }
    let header = read_file_header(path)?;
    Ok(has_secret_markers(&header))
}

/// Classify a secret-shaped blob by content (first 1024 bytes) then extension.
#[cfg(test)]
pub(crate) fn classify_blob(path: &Path) -> (&'static str, &'static str) {
    let header = fs::read(path)
        .ok()
        .map(|bytes| bytes.into_iter().take(1024).collect::<Vec<u8>>());

    if let Some(ref bytes) = header
        && let Some(hit) = classify_by_content(bytes, !is_source_like_extension(path))
    {
        return hit;
    }

    classify_by_extension(path)
}


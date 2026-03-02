//! No-blob policy enforcement tests.
//!
//! These tests ensure that no secret-shaped content (PEM files, DER blobs,
//! hardcoded key material) is checked into the repository's test and fixture
//! directories. They complement the `cargo xtask no-blob` gate.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must live one level below workspace root")
        .to_path_buf()
}

/// Recursively collect files under `dir`, skipping `.git` and `target`.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, ".git" | "target" | ".cargo" | "node_modules") {
                continue;
            }
            collect_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// Return all `.rs` files under `crates/` and `tests/` directories.
fn rust_test_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_files(&root.join("crates"), &mut files);
    collect_files(&root.join("tests"), &mut files);
    files.retain(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"));
    files
}

/// PEM header markers that indicate actual key material (not just format checks).
const PEM_PRIVATE_HEADERS: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
];

/// Check whether a line contains a PEM header inside a string literal that
/// represents an actual embedded key (multi-line base64 block), as opposed to
/// an assertion, format check, or deliberate negative-fixture input.
fn is_embedded_pem_blob(content: &str, line_idx: usize, lines: &[&str]) -> bool {
    let line = lines[line_idx];
    let trimmed = line.trim();

    // Assertion / comment / snapshot contexts are not embedded blobs.
    let safe_keywords = [
        "assert",
        "contains(",
        "starts_with(",
        "ends_with(",
        "expect(",
        "snapshot",
        "// ",
        "/// ",
        "//!",
        "insta::",
    ];
    if safe_keywords.iter().any(|kw| trimmed.contains(kw)) {
        return false;
    }

    // Named `const` / `static` PEM fixtures used as *inputs* to corruption or
    // parsing functions are deliberate test helpers, not accidental leaks.
    // Walk backwards to find the enclosing `const`/`static` declaration.
    for prev_idx in (0..=line_idx).rev() {
        let prev = lines[prev_idx].trim();
        if prev.starts_with("const ") || prev.starts_with("static ") {
            return false;
        }
        // Stop searching once we hit a blank line or closing brace (different scope).
        if prev.is_empty() || prev == "}" || prev.starts_with("fn ") {
            break;
        }
    }

    // Look for a multi-line base64 block following the PEM header (actual key material).
    let mut base64_lines = 0;
    for subsequent in lines.iter().skip(line_idx + 1) {
        let t = subsequent.trim().trim_matches('"').trim_matches('\\');
        if t.starts_with("-----END") {
            break;
        }
        if t.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && t.len() > 20
        {
            base64_lines += 1;
        } else {
            break;
        }
    }

    // 3+ lines of base64 after the header indicates an embedded blob.
    let _ = content;
    base64_lines >= 3
}

// ---------------------------------------------------------------------------
// 1. No PEM private key headers as embedded blobs in test files
// ---------------------------------------------------------------------------

#[test]
fn no_embedded_pem_private_keys_in_test_files() {
    let mut violations = Vec::new();

    for path in rust_test_files() {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            for header in PEM_PRIVATE_HEADERS {
                if line.contains(header) && is_embedded_pem_blob(&content, idx, &lines) {
                    violations.push(format!("{}:{}", path.display(), idx + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found embedded PEM private key blobs in test files:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. No DER files or DER magic bytes in checked-in files
// ---------------------------------------------------------------------------

#[test]
fn no_der_files_checked_in() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_files(&root, &mut files);

    let der_extensions = ["der", "key", "p12", "pfx", "crt", "cer"];
    let violations: Vec<_> = files
        .iter()
        .filter(|p| {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            der_extensions.contains(&ext.as_str())
        })
        .map(|p| p.strip_prefix(&root).unwrap_or(p).display().to_string())
        .collect();

    assert!(
        violations.is_empty(),
        "found DER/certificate files checked in:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 3. No standalone PEM files checked in
// ---------------------------------------------------------------------------

#[test]
fn no_pem_files_checked_in() {
    let root = workspace_root();
    let mut files = Vec::new();
    collect_files(&root, &mut files);

    let violations: Vec<_> = files
        .iter()
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pem"))
                .unwrap_or(false)
        })
        .map(|p| p.strip_prefix(&root).unwrap_or(p).display().to_string())
        .collect();

    assert!(
        violations.is_empty(),
        "found .pem files checked in:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 4. No large base64-encoded key blobs in test source files
// ---------------------------------------------------------------------------

#[test]
fn no_hardcoded_base64_key_blobs_in_test_files() {
    // A "key blob" is a string literal containing 200+ characters of pure base64
    // (indicative of an embedded key rather than a test assertion about format).
    let base64_min_len = 200;
    let mut violations = Vec::new();

    for path in rust_test_files() {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments and assertion lines
            if trimmed.starts_with("//") || trimmed.contains("assert") {
                continue;
            }
            // Look for string literals with long base64 content
            if let Some(start) = trimmed.find('"')
                && let Some(end) = trimmed[start + 1..].find('"')
            {
                let literal = &trimmed[start + 1..start + 1 + end];
                if literal.len() >= base64_min_len
                    && literal
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                {
                    violations.push(format!("{}:{}", path.display(), line_no + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found hardcoded base64 key blobs in test files:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 5. No hardcoded JWK private key blobs in test files
// ---------------------------------------------------------------------------

#[test]
fn no_hardcoded_jwk_private_keys_in_test_files() {
    // A hardcoded JWK private key contains `"d":` (the private exponent)
    // together with `"kty":` in a JSON-like string literal.
    let mut violations = Vec::new();

    for path in rust_test_files() {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            // Skip comments and assertions
            if trimmed.starts_with("//") || trimmed.contains("assert") {
                continue;
            }
            // Look for JWK-shaped JSON with private key component "d"
            // that spans a single line (hardcoded blob)
            if trimmed.contains("\"kty\"") && trimmed.contains("\"d\"") {
                // Ensure it's a long enough blob to be a real key (not a field name check)
                if trimmed.len() > 100 {
                    violations.push(format!("{}:{}", path.display(), line_no + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found hardcoded JWK private key blobs in test files:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 6. .gitignore excludes temp/artifact directories
// ---------------------------------------------------------------------------

#[test]
fn gitignore_excludes_temp_directories() {
    let root = workspace_root();
    let gitignore =
        std::fs::read_to_string(root.join(".gitignore")).expect(".gitignore must exist");

    let required_patterns = [
        "target",
        "proptest-regressions",
        "fuzz/artifacts",
        "fuzz/corpus",
        "mutants.out",
    ];

    let mut missing = Vec::new();
    for pattern in &required_patterns {
        if !gitignore.lines().any(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with('#') && trimmed.contains(pattern)
        }) {
            missing.push(*pattern);
        }
    }

    assert!(
        missing.is_empty(),
        ".gitignore missing required exclusions:\n  {}",
        missing.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 7. Snapshot files contain shape assertions, not raw key material
// ---------------------------------------------------------------------------

#[test]
fn snapshot_files_contain_shapes_not_raw_keys() {
    let root = workspace_root();
    let mut snap_files = Vec::new();
    collect_files(&root.join("crates"), &mut snap_files);
    snap_files.retain(|p| p.extension().and_then(|e| e.to_str()) == Some("snap"));

    let mut violations = Vec::new();
    for path in &snap_files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if !line.contains("-----BEGIN") {
                continue;
            }
            // Count base64 lines following the header
            let mut base64_lines = 0;
            for subsequent in lines.iter().skip(idx + 1) {
                let t = subsequent.trim();
                if t.starts_with("-----END") || t.is_empty() {
                    break;
                }
                if t.len() > 20
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                {
                    base64_lines += 1;
                } else {
                    break;
                }
            }
            if base64_lines >= 3 {
                let rel = path.strip_prefix(&root).unwrap_or(path);
                violations.push(format!("{}:{}", rel.display(), idx + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "snapshot files contain raw key material (should be shape-only):\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 8. No fixture directories with checked-in secret files
// ---------------------------------------------------------------------------

#[test]
fn no_secret_fixture_directories() {
    let root = workspace_root();
    let fixture_dirs = ["fixtures", "testdata", "test_fixtures", "test_data"];

    let mut violations = Vec::new();
    for dir_name in &fixture_dirs {
        let dir = root.join(dir_name);
        if !dir.exists() {
            continue;
        }
        let mut files = Vec::new();
        collect_files(&dir, &mut files);

        let secret_extensions = ["pem", "der", "key", "p12", "pfx", "crt", "cer", "jwk"];
        for file in &files {
            let ext = file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if secret_extensions.contains(&ext.as_str()) {
                let rel = file.strip_prefix(&root).unwrap_or(file);
                violations.push(rel.display().to_string());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "found secret files in fixture directories:\n  {}",
        violations.join("\n  ")
    );
}

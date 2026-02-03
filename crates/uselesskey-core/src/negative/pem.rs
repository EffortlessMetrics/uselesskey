#[derive(Clone, Copy, Debug)]
pub enum CorruptPem {
    /// Replace the BEGIN header line.
    BadHeader,
    /// Replace the END footer line.
    BadFooter,
    /// Insert a non-base64 line into the body.
    BadBase64,
    /// Truncate the PEM string to `n` bytes.
    Truncate { bytes: usize },
    /// Add an extra blank line in the body.
    ExtraBlankLine,
}

/// Apply a deterministic corruption to a PEM-encoded string.
///
/// This is intentionally simple: the point is to exercise failure paths, not to be clever.
pub fn corrupt_pem(pem: &str, how: CorruptPem) -> String {
    match how {
        CorruptPem::BadHeader => replace_first_line(pem, "-----BEGIN CORRUPTED KEY-----"),
        CorruptPem::BadFooter => replace_last_line(pem, "-----END CORRUPTED KEY-----"),
        CorruptPem::BadBase64 => inject_bad_base64_line(pem),
        CorruptPem::Truncate { bytes } => pem.chars().take(bytes).collect(),
        CorruptPem::ExtraBlankLine => inject_blank_line(pem),
    }
}

fn replace_first_line(pem: &str, replacement: &str) -> String {
    let mut lines = pem.lines();
    let _first = lines.next();

    let mut out = String::new();
    out.push_str(replacement);
    out.push('\n');

    for l in lines {
        out.push_str(l);
        out.push('\n');
    }

    out
}

fn replace_last_line(pem: &str, replacement: &str) -> String {
    let mut all: Vec<&str> = pem.lines().collect();
    if all.is_empty() {
        return replacement.to_string();
    }
    let last_idx = all.len() - 1;
    all[last_idx] = replacement;

    let mut out = String::new();
    for l in all {
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn inject_bad_base64_line(pem: &str) -> String {
    // Put garbage after the header, before any base64.
    let mut lines: Vec<&str> = pem.lines().collect();
    if lines.len() < 3 {
        return format!("{pem}\nTHIS_IS_NOT_BASE64!!!\n");
    }

    // Insert after header.
    lines.insert(1, "THIS_IS_NOT_BASE64!!!");

    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn inject_blank_line(pem: &str) -> String {
    let mut lines: Vec<&str> = pem.lines().collect();
    if lines.len() < 3 {
        return format!("{pem}\n\n");
    }
    lines.insert(1, "");
    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

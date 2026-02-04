/// Strategies for corrupting PEM-encoded data.
///
/// Each variant produces a different kind of malformed PEM that can be used
/// to test error handling in PEM parsers.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::{corrupt_pem, CorruptPem};
///
/// let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n";
///
/// // Each variant tests a different failure mode
/// let bad_header = corrupt_pem(pem, CorruptPem::BadHeader);
/// let bad_footer = corrupt_pem(pem, CorruptPem::BadFooter);
/// let bad_base64 = corrupt_pem(pem, CorruptPem::BadBase64);
/// let truncated = corrupt_pem(pem, CorruptPem::Truncate { bytes: 30 });
/// let extra_blank = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
/// ```
#[derive(Clone, Copy, Debug)]
pub enum CorruptPem {
    /// Replace the BEGIN header line with `-----BEGIN CORRUPTED KEY-----`.
    ///
    /// Tests parsers that validate the header label.
    BadHeader,
    /// Replace the END footer line with `-----END CORRUPTED KEY-----`.
    ///
    /// Tests parsers that validate header/footer consistency.
    BadFooter,
    /// Insert a non-base64 line (`THIS_IS_NOT_BASE64!!!`) into the body.
    ///
    /// Tests parsers that validate base64 encoding.
    BadBase64,
    /// Truncate the PEM string to `bytes` characters.
    ///
    /// Tests parsers handling incomplete input.
    Truncate { bytes: usize },
    /// Add an extra blank line in the body.
    ///
    /// Tests parsers with strict line handling.
    ExtraBlankLine,
}

/// Apply a deterministic corruption to a PEM-encoded string.
///
/// This is intentionally simple: the point is to exercise failure paths, not to be clever.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::{corrupt_pem, CorruptPem};
///
/// let pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANB==\n-----END PRIVATE KEY-----\n";
///
/// // Corrupt the header - parsers expecting "PRIVATE KEY" will fail
/// let bad = corrupt_pem(pem, CorruptPem::BadHeader);
/// assert!(bad.starts_with("-----BEGIN CORRUPTED KEY-----"));
///
/// // Corrupt the footer
/// let bad = corrupt_pem(pem, CorruptPem::BadFooter);
/// assert!(bad.contains("-----END CORRUPTED KEY-----"));
///
/// // Add invalid base64
/// let bad = corrupt_pem(pem, CorruptPem::BadBase64);
/// assert!(bad.contains("THIS_IS_NOT_BASE64"));
///
/// // Truncate to specific length
/// let bad = corrupt_pem(pem, CorruptPem::Truncate { bytes: 10 });
/// assert_eq!(bad.len(), 10);
/// ```
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

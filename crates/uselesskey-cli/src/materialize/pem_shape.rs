use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use uselesskey_core::Seed;

use crate::MaterializeError;

pub(super) fn pem_block_shape(
    seed: &str,
    label: &str,
    len: Option<usize>,
) -> Result<Vec<u8>, MaterializeError> {
    let len = len.unwrap_or(256);
    let seed = Seed::from_text(seed);
    let mut bytes = vec![0u8; len];
    seed.fill_bytes(&mut bytes);
    let payload = BASE64_STD.encode(bytes);
    let block_label = normalize_pem_label(label);
    let mut out = String::new();
    let _ = writeln!(&mut out, "-----BEGIN {block_label}-----");
    for chunk in payload.as_bytes().chunks(64) {
        let _ = writeln!(
            &mut out,
            "{}",
            std::str::from_utf8(chunk).map_err(|err| {
                MaterializeError::InvalidManifest(format!(
                    "generated base64 payload was not utf-8: {err}"
                ))
            })?
        );
    }
    let _ = writeln!(&mut out, "-----END {block_label}-----");
    Ok(out.into_bytes())
}

fn normalize_pem_label(label: &str) -> String {
    let normalized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if normalized.is_empty() {
        "SECRET".to_string()
    } else {
        normalized
    }
}

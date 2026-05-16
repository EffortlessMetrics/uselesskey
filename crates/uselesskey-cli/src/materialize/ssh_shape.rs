use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use uselesskey_core::Seed;

pub(super) fn ssh_public_key_shape(seed: &str, label: &str) -> Vec<u8> {
    let seed = Seed::from_text(seed);
    let mut bytes = [0u8; 32];
    seed.fill_bytes(&mut bytes);
    format!(
        "ssh-ed25519 {} {}\n",
        BASE64_STD.encode(bytes),
        normalize_ssh_comment(label)
    )
    .into_bytes()
}

fn normalize_ssh_comment(label: &str) -> String {
    let normalized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if normalized.is_empty() {
        "fixture".to_string()
    } else {
        normalized
    }
}

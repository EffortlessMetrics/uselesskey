use uselesskey_core::Seed;

pub(super) fn entropy_bytes(seed: &str, len: Option<usize>) -> Vec<u8> {
    let len = len.unwrap_or(32);
    let seed = Seed::from_text(seed);
    let mut bytes = vec![0u8; len];
    seed.fill_bytes(&mut bytes);
    bytes
}

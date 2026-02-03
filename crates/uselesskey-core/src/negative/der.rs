/// Truncate DER bytes to `len` bytes.
///
/// If `len >= der.len()`, returns the original bytes.
pub fn truncate_der(der: &[u8], len: usize) -> Vec<u8> {
    if len >= der.len() {
        return der.to_vec();
    }
    der[..len].to_vec()
}

/// Flip one byte at `offset` (xor with `0x01`).
///
/// If `offset` is out of range, returns the original bytes.
pub fn flip_byte(der: &[u8], offset: usize) -> Vec<u8> {
    if offset >= der.len() {
        return der.to_vec();
    }

    let mut out = der.to_vec();
    out[offset] ^= 0x01;
    out
}

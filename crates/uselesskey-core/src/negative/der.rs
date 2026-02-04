/// Truncate DER bytes to `len` bytes.
///
/// If `len >= der.len()`, returns the original bytes unchanged.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::truncate_der;
///
/// let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09];
///
/// // Truncate to 4 bytes
/// let truncated = truncate_der(&der, 4);
/// assert_eq!(truncated, vec![0x30, 0x82, 0x01, 0x22]);
///
/// // Truncate beyond length returns original
/// let same = truncate_der(&der, 100);
/// assert_eq!(same, der);
/// ```
pub fn truncate_der(der: &[u8], len: usize) -> Vec<u8> {
    if len >= der.len() {
        return der.to_vec();
    }
    der[..len].to_vec()
}

/// Flip one byte at `offset` (XOR with `0x01`).
///
/// If `offset` is out of range, returns the original bytes unchanged.
///
/// This is useful for creating DER that is structurally invalid,
/// such as corrupting ASN.1 tags or length bytes.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::flip_byte;
///
/// let der = vec![0x30, 0x82, 0x01, 0x22]; // SEQUENCE tag at byte 0
///
/// // Flip the tag byte: 0x30 XOR 0x01 = 0x31
/// let flipped = flip_byte(&der, 0);
/// assert_eq!(flipped[0], 0x31);
/// assert_eq!(flipped[1..], der[1..]); // Rest unchanged
///
/// // Flip at invalid offset returns original
/// let same = flip_byte(&der, 100);
/// assert_eq!(same, der);
/// ```
pub fn flip_byte(der: &[u8], offset: usize) -> Vec<u8> {
    if offset >= der.len() {
        return der.to_vec();
    }

    let mut out = der.to_vec();
    out[offset] ^= 0x01;
    out
}

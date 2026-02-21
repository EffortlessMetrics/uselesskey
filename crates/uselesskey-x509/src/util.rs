//! Shared utilities for X.509 certificate generation.

use rand_core::RngCore;
use rcgen::SerialNumber;
use time::OffsetDateTime;

/// Deterministic base time from a pre-configured BLAKE3 hasher.
///
/// Returns a time spread across ~1 year from 2025-01-01 to 2026-01-01.
/// This ensures "good" leaf certs (365-day validity) are still currently valid
/// and "good" root CAs (3650-day validity) are valid until 2035+.
pub fn deterministic_base_time(hasher: blake3::Hasher) -> OffsetDateTime {
    // 2025-01-01T00:00:00Z
    const EPOCH_UNIX: i64 = 1_735_689_600;
    let epoch = OffsetDateTime::from_unix_timestamp(EPOCH_UNIX)
        .expect("failed to construct deterministic epoch");

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let day_offset = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 365;
    epoch + time::Duration::days(day_offset as i64)
}

/// Deterministic serial number drawn from an RNG.
///
/// Produces a 16-byte positive serial number (high bit cleared).
pub fn deterministic_serial_number(rng: &mut impl RngCore) -> SerialNumber {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    // Ensure positive serial number by clearing the high bit.
    bytes[0] &= 0x7F;
    SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn deterministic_base_time_is_within_one_year() {
        // 2025-01-01T00:00:00Z
        const EPOCH_UNIX: i64 = 1_735_689_600;
        let epoch = OffsetDateTime::from_unix_timestamp(EPOCH_UNIX).unwrap();

        let base = deterministic_base_time(blake3::Hasher::new());
        let max = epoch + time::Duration::days(364);

        assert!(base >= epoch, "base time should be after epoch");
        assert!(base <= max, "base time should be within 365 days");
    }

    #[test]
    fn deterministic_serial_number_is_positive_and_16_bytes() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();

        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0] & 0x80, 0, "high bit should be cleared");

        // Second seed that likely produces a high-bit-set first byte
        let mut rng2 = ChaCha20Rng::from_seed([0xFF; 32]);
        let serial2 = deterministic_serial_number(&mut rng2);
        let bytes2 = serial2.to_bytes();
        assert_eq!(bytes2.len(), 16);
        assert_eq!(
            bytes2[0] & 0x80,
            0,
            "high bit should be cleared for any seed"
        );
    }
}

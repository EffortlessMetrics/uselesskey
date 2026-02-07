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

//! Deterministic X.509 derivation helpers.
//!
//! This crate centralizes deterministic logic shared by X.509 fixture producers:
//! - deterministic base-time derivation from stable identity inputs
//! - deterministic positive serial number generation
//! - length-prefixed hashing to avoid input-boundary collisions
//!
//! # Examples
//!
//! Derive a deterministic base time from identity parts:
//!
//! ```
//! use uselesskey_core_x509_derive::{
//!     deterministic_base_time_from_parts, BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS,
//! };
//! use time::OffsetDateTime;
//!
//! let t = deterministic_base_time_from_parts(&[b"my-label", b"leaf"]);
//!
//! let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
//! let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));
//! assert!(t >= epoch && t < max);
//! ```
//!
//! Generate a deterministic serial number from a seed:
//!
//! ```
//! use uselesskey_core_x509_derive::{deterministic_serial_number, SERIAL_NUMBER_BYTES};
//! use uselesskey_core_seed::Seed;
//!
//! let serial = deterministic_serial_number(Seed::new([42u8; 32]));
//! let bytes = serial.to_bytes();
//! assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
//! assert_eq!(bytes[0] & 0x80, 0, "high bit must be cleared");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rcgen::SerialNumber;
use time::OffsetDateTime;
use uselesskey_core_hash::Hasher;
pub use uselesskey_core_hash::write_len_prefixed;
use uselesskey_core_seed::Seed;

/// 2025-01-01T00:00:00Z used as the deterministic X.509 epoch.
pub const BASE_TIME_EPOCH_UNIX: i64 = 1_735_689_600;

/// Number of days in the deterministic base-time window.
pub const BASE_TIME_WINDOW_DAYS: u32 = 365;

/// Fixed serial-number byte length for deterministic certificate/CRL serials.
pub const SERIAL_NUMBER_BYTES: usize = 16;

/// Compute deterministic base time from length-prefixed identity parts.
///
/// Every part is hashed with a 32-bit length prefix to avoid boundary ambiguity.
pub fn deterministic_base_time_from_parts(parts: &[&[u8]]) -> OffsetDateTime {
    let mut hasher = Hasher::new();
    for part in parts {
        write_len_prefixed(&mut hasher, part);
    }
    deterministic_base_time(hasher)
}

/// Deterministic base time from a pre-configured BLAKE3 hasher.
///
/// Returns a time spread across one year from 2025-01-01 to 2026-01-01.
pub fn deterministic_base_time(hasher: Hasher) -> OffsetDateTime {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX)
        .expect("failed to construct deterministic X.509 epoch");

    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let day_offset =
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % BASE_TIME_WINDOW_DAYS;
    epoch + time::Duration::days(i64::from(day_offset))
}

/// Deterministic serial number derived from seed material.
///
/// Produces a 16-byte positive serial number (high bit cleared).
pub fn deterministic_serial_number(seed: Seed) -> SerialNumber {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    deterministic_serial_number_with_rng(&mut rng)
}

fn deterministic_serial_number_with_rng(rng: &mut impl RngCore) -> SerialNumber {
    let mut bytes = [0u8; SERIAL_NUMBER_BYTES];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7F;
    SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core_seed::Seed;

    #[test]
    fn deterministic_base_time_is_within_one_year() {
        let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
        let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));

        let base = deterministic_base_time(Hasher::new());
        assert!(base >= epoch, "base time should be after epoch");
        assert!(base <= max, "base time should be within one year");
    }

    #[test]
    fn deterministic_base_time_is_deterministic() {
        let a = deterministic_base_time_from_parts(&[b"label", b"leaf", b"root", b"2048"]);
        let b = deterministic_base_time_from_parts(&[b"label", b"leaf", b"root", b"2048"]);
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_base_time_from_parts_is_boundary_safe() {
        let a = deterministic_base_time_from_parts(&[b"ab", b"c"]);
        let b = deterministic_base_time_from_parts(&[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_serial_number_is_positive_and_fixed_size() {
        let serial = deterministic_serial_number(Seed::new([7u8; 32]));
        let bytes = serial.to_bytes();

        assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
        assert_eq!(bytes[0] & 0x80, 0, "high bit should be cleared");
    }

    #[test]
    fn deterministic_serial_number_is_seed_stable() {
        assert_eq!(
            deterministic_serial_number(Seed::new([42u8; 32])).to_bytes(),
            deterministic_serial_number(Seed::new([42u8; 32])).to_bytes()
        );
    }

    #[test]
    fn deterministic_serial_number_varies_by_seed() {
        assert_ne!(
            deterministic_serial_number(Seed::new([1u8; 32])).to_bytes(),
            deterministic_serial_number(Seed::new([2u8; 32])).to_bytes()
        );
    }
}

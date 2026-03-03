use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    // ── deterministic_base_time_from_parts ───────────────────────────

    #[test]
    fn base_time_always_within_epoch_window(
        parts in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32),
            0..8,
        ),
    ) {
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let t = deterministic_base_time_from_parts(&refs);

        let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
        let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));
        prop_assert!(t >= epoch, "base time {t} is before epoch {epoch}");
        prop_assert!(t < max, "base time {t} is at or after max {max}");
    }

    #[test]
    fn base_time_is_deterministic(
        parts in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32),
            0..8,
        ),
    ) {
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let a = deterministic_base_time_from_parts(&refs);
        let b = deterministic_base_time_from_parts(&refs);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn base_time_boundary_safe(
        left in proptest::collection::vec(any::<u8>(), 1..16),
        right in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
        let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

        // Original split produces a valid, in-range, deterministic result
        let original_a = deterministic_base_time_from_parts(&[&left, &right]);
        let original_b = deterministic_base_time_from_parts(&[&left, &right]);
        prop_assert_eq!(original_a, original_b, "must be deterministic");
        prop_assert!(original_a >= epoch, "base time {original_a} before epoch {epoch}");
        prop_assert!(original_a < max, "base time {original_a} at or after max {max}");

        // Alternate split also produces a valid, in-range, deterministic result
        let combined: Vec<u8> = left.iter().chain(right.iter()).copied().collect();
        let split_at = if left.len() > 1 { left.len() - 1 } else { left.len() + 1 };
        prop_assume!(split_at < combined.len());
        let (alt_left, alt_right) = combined.split_at(split_at);

        let alternate_a = deterministic_base_time_from_parts(&[alt_left, alt_right]);
        let alternate_b = deterministic_base_time_from_parts(&[alt_left, alt_right]);
        prop_assert_eq!(alternate_a, alternate_b, "alternate must be deterministic");
        prop_assert!(alternate_a >= epoch, "alternate {alternate_a} before epoch {epoch}");
        prop_assert!(alternate_a < max, "alternate {alternate_a} at or after max {max}");
    }

    // ── deterministic_serial_number ──────────────────────────────────

    #[test]
    fn serial_always_positive(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();
        prop_assert_eq!(bytes[0] & 0x80, 0, "high bit must be cleared");
    }

    #[test]
    fn serial_correct_length(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let serial = deterministic_serial_number(&mut rng);
        prop_assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
    }

    #[test]
    fn serial_deterministic_for_same_seed(seed in any::<[u8; 32]>()) {
        let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed));
        let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed));
        prop_assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn serial_differs_for_different_seeds(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);
        let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed_a));
        let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed_b));
        prop_assert_ne!(a.to_bytes(), b.to_bytes());
    }
}

use proptest::prelude::*;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use time::OffsetDateTime;
use uselesskey_core_x509_derive::{
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
};
use uselesskey_core_hash::Hasher;

#[test]
fn base_time_from_parts_is_deterministic() {
    let a = deterministic_base_time_from_parts(&[b"domain", b"label", b"leaf"]);
    let b = deterministic_base_time_from_parts(&[b"domain", b"label", b"leaf"]);
    assert_eq!(a, b, "same inputs must produce the same time");
}

#[test]
fn base_time_from_parts_varies_with_input() {
    let a = deterministic_base_time_from_parts(&[b"alpha"]);
    let b = deterministic_base_time_from_parts(&[b"beta"]);
    assert_ne!(a, b, "different inputs should produce different times");
}

#[test]
fn base_time_stays_within_epoch_window() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    for i in 0u32..200 {
        let bytes = i.to_be_bytes();
        let parts: Vec<&[u8]> = vec![&bytes];
        let t = deterministic_base_time_from_parts(&parts);
        assert!(t >= epoch, "time {t} is before epoch {epoch}");
        assert!(t < max, "time {t} is at or after max {max}");
    }
}

#[test]
fn serial_number_is_positive() {
    let mut rng = ChaCha8Rng::from_seed([99u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes[0] & 0x80, 0, "high bit must be cleared for positive serial");
}

#[test]
fn serial_number_is_16_bytes() {
    let mut rng = ChaCha8Rng::from_seed([5u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn serial_number_deterministic_from_seed() {
    let seed = [42u8; 32];
    let mut rng_a = ChaCha8Rng::from_seed(seed);
    let mut rng_b = ChaCha8Rng::from_seed(seed);

    let a = deterministic_serial_number(&mut rng_a).to_bytes();
    let b = deterministic_serial_number(&mut rng_b).to_bytes();
    assert_eq!(a, b, "same seed must yield identical serial numbers");
}

#[test]
fn write_len_prefixed_format() {
    let content = b"hello";

    // Build expected hash: 4-byte big-endian length + content
    let mut expected = Hasher::new();
    expected.update(&(content.len() as u32).to_be_bytes());
    expected.update(content);

    // Build actual hash via write_len_prefixed
    let mut actual = Hasher::new();
    write_len_prefixed(&mut actual, content);

    assert_eq!(actual.finalize(), expected.finalize());
}

proptest! {
    #[test]
    fn proptest_serial_always_positive(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha8Rng::from_seed(seed);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();
        prop_assert_eq!(bytes[0] & 0x80, 0, "high bit must be cleared");
    }
}

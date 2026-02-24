use blake3::Hasher;
use uselesskey_core_hash::{hash32, write_len_prefixed};

#[test]
fn integration_matches_length_prefixed_spec_behavior() {
    let first = b"fixture";
    let second = b"helpers";

    let mut left = Hasher::new();
    write_len_prefixed(&mut left, first);
    write_len_prefixed(&mut left, second);
    let left = left.finalize();

    let mut right = Hasher::new();
    right.update(&u32::try_from(first.len()).unwrap_or(u32::MAX).to_be_bytes());
    right.update(first);
    right.update(
        &u32::try_from(second.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    right.update(second);
    let right = right.finalize();

    assert_eq!(left, right);
}

#[test]
fn integration_keeps_direct_hash_compatibility() {
    let fixture = b"deterministic-core-hash";
    assert_eq!(hash32(fixture), blake3::hash(fixture));
}

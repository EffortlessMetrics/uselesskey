#![no_main]

use blake3::Hasher;
use libfuzzer_sys::fuzz_target;
use uselesskey_core_hash::{hash32, write_len_prefixed};

fuzz_target!(|data: &[u8]| {
    let _ = hash32(data);

    let mut hasher_a = Hasher::new();
    write_len_prefixed(&mut hasher_a, data);
    let left = hasher_a.finalize();

    let mut hasher_b = Hasher::new();
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    hasher_b.update(&len.to_be_bytes());
    hasher_b.update(data);
    let right = hasher_b.finalize();

    assert_eq!(left, right);
});

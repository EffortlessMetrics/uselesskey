#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey::negative::{flip_byte, truncate_der};

fuzz_target!(|data: &[u8]| {
    // Length derived from first byte (if present).
    let len = data.get(0).copied().unwrap_or(0) as usize;
    let _ = truncate_der(data, len);

    // Offset derived from second byte (if present).
    let off = data.get(1).copied().unwrap_or(0) as usize;
    let _ = flip_byte(data, off);
});

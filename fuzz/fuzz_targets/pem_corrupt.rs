#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey::negative::{corrupt_pem, CorruptPem};

fuzz_target!(|data: &[u8]| {
    // Treat arbitrary bytes as UTF-8-ish and ensure we never panic.
    let s = String::from_utf8_lossy(data);

    let _ = corrupt_pem(&s, CorruptPem::BadHeader);
    let _ = corrupt_pem(&s, CorruptPem::BadFooter);
    let _ = corrupt_pem(&s, CorruptPem::BadBase64);
    let _ = corrupt_pem(&s, CorruptPem::ExtraBlankLine);
    let _ = corrupt_pem(&s, CorruptPem::Truncate { bytes: 16 });
});

#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_negative_pem::{corrupt_pem, corrupt_pem_deterministic, CorruptPem};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = corrupt_pem(&s, CorruptPem::BadHeader);
    let _ = corrupt_pem(&s, CorruptPem::BadFooter);
    let _ = corrupt_pem(&s, CorruptPem::BadBase64);
    let _ = corrupt_pem(&s, CorruptPem::ExtraBlankLine);
    let _ = corrupt_pem(&s, CorruptPem::Truncate { bytes: 16 });

    let _ = corrupt_pem_deterministic(&s, &s);
});

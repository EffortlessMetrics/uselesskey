#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_negative_pem::{corrupt_pem, corrupt_pem_deterministic, CorruptPem};

// Fuzz PEM corruption with realistic PEM-shaped input.
// Unlike `core_negative_pem` (which feeds raw bytes), this target wraps
// fuzz data inside a PEM-shaped envelope so the corruption functions
// exercise their internal parsing paths more deeply.
fuzz_target!(|data: &[u8]| {
    // Cap input size to avoid large allocations.
    let data = &data[..data.len().min(1024)];
    let body = String::from_utf8_lossy(data);

    // Build a realistic PEM envelope around fuzz data.
    let pem = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"
    );

    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 0 },
        CorruptPem::Truncate { bytes: 1 },
        CorruptPem::Truncate { bytes: 16 },
        CorruptPem::Truncate { bytes: 256 },
        CorruptPem::Truncate {
            bytes: data.len(),
        },
    ];

    for variant in &variants {
        let corrupted = corrupt_pem(&pem, variant.clone());
        // The corrupted output must differ from the original for non-trivial input.
        // We don't assert equality — we only care about panic-freedom.
        let _ = corrupted;
    }

    // Also exercise deterministic corruption with varying variant strings.
    let variant_str = String::from_utf8_lossy(data);
    let _ = corrupt_pem_deterministic(&pem, &variant_str);

    // Feed the corrupted output back through corruption (double-corrupt).
    let once = corrupt_pem(&pem, CorruptPem::BadBase64);
    let _ = corrupt_pem(&once, CorruptPem::BadHeader);
    let _ = corrupt_pem(&once, CorruptPem::Truncate { bytes: 8 });
});

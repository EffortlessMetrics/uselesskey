#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey::Seed;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Ok(seed) = Seed::from_env_value(&input) {
        assert_eq!(format!("{seed:?}"), "Seed(**redacted**)");
    }
});

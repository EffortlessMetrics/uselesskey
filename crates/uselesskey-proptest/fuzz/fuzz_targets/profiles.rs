#![no_main]

use libfuzzer_sys::fuzz_target;
use uselesskey_proptest::fuzz::fuzz_profiles_no_panic;

fuzz_target!(|data: &[u8]| {
    fuzz_profiles_no_panic(data);
});

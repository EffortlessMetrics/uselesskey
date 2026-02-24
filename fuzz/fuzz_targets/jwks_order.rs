#![no_main]

use libfuzzer_sys::fuzz_target;
use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Clone)]
struct FixtureItem {
    kid: String,
    index: u32,
}

impl HasKid for FixtureItem {
    fn kid(&self) -> &str {
        &self.kid
    }
}

fn kid_from_bytes(bytes: &[u8]) -> String {
    let mut kid = String::new();
    for &b in bytes.iter().take(4) {
        kid.push(char::from(b'a' + (b % 26)));
    }
    if kid.is_empty() {
        kid.push('k');
    }
    kid
}

fn verify_stability(items: &[FixtureItem]) {
    for pair in items.windows(2) {
        let left = &pair[0];
        let right = &pair[1];
        let kid_cmp = left.kid.cmp(&right.kid);
        assert!(
            kid_cmp != std::cmp::Ordering::Greater,
            "order must be nondecreasing: {} should come before {}",
            left.kid,
            right.kid,
        );
    }

    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            let a = &items[i];
            let b = &items[j];
            if a.kid == b.kid {
                assert!(a.index < b.index, "stable tie-break by insertion for kid {}", a.kid);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut sorter = KidSorted::new();
    let mut expected = Vec::<FixtureItem>::new();

    for (i, chunk) in data.chunks(8).take(128).enumerate() {
        let item = FixtureItem {
            kid: kid_from_bytes(chunk),
            index: i as u32,
        };
        sorter.push(item.clone());
        expected.push(item);
    }

    expected.sort_by(|a, b| a.kid.cmp(&b.kid).then(a.index.cmp(&b.index)));
    let result = sorter.build();

    assert_eq!(result.len(), expected.len());
    for (left, right) in result.iter().zip(expected.iter()) {
        assert_eq!(left.kid(), right.kid);
        assert_eq!(left.index, right.index);
    }

    verify_stability(&result);
});

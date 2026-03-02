use proptest::prelude::*;
use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Debug, Clone)]
struct TestKey {
    kid: String,
    index: usize,
}

impl HasKid for TestKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn output_is_sorted_by_kid(kids in proptest::collection::vec("[a-z]{1,8}", 0..32)) {
        let mut sorter = KidSorted::new();
        for (i, kid) in kids.iter().enumerate() {
            sorter.push(TestKey { kid: kid.clone(), index: i });
        }
        let result = sorter.build();
        for window in result.windows(2) {
            prop_assert!(
                window[0].kid() <= window[1].kid(),
                "not sorted: {:?} > {:?}",
                window[0].kid(),
                window[1].kid()
            );
        }
    }

    #[test]
    fn stable_sort_preserves_insertion_order(
        count in 2usize..16,
        kid in "[a-z]{1,4}",
    ) {
        let mut sorter = KidSorted::new();
        for i in 0..count {
            sorter.push(TestKey { kid: kid.clone(), index: i });
        }
        let result = sorter.build();
        for (pos, item) in result.iter().enumerate() {
            prop_assert_eq!(
                item.index, pos,
                "insertion order not preserved at position {}",
                pos
            );
        }
    }

    #[test]
    fn build_preserves_all_items(kids in proptest::collection::vec("[a-z]{1,8}", 0..32)) {
        let mut sorter = KidSorted::new();
        for (i, kid) in kids.iter().enumerate() {
            sorter.push(TestKey { kid: kid.clone(), index: i });
        }
        let result = sorter.build();
        prop_assert_eq!(result.len(), kids.len());
    }

    #[test]
    fn ordering_is_deterministic(kids in proptest::collection::vec("[a-z]{1,8}", 0..32)) {
        let build = |kids: &[String]| {
            let mut sorter = KidSorted::new();
            for (i, kid) in kids.iter().enumerate() {
                sorter.push(TestKey { kid: kid.clone(), index: i });
            }
            sorter.build().into_iter().map(|k| (k.kid, k.index)).collect::<Vec<_>>()
        };
        prop_assert_eq!(build(&kids), build(&kids));
    }

    #[test]
    fn empty_collection_builds_empty(dummy in 0u8..1) {
        let _ = dummy;
        let sorter: KidSorted<TestKey> = KidSorted::new();
        let result = sorter.build();
        prop_assert!(result.is_empty());
    }
}

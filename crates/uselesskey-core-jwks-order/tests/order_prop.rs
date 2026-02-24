use uselesskey_core_jwks_order::{HasKid, KidSorted};
use proptest::prelude::*;

#[derive(Debug, Clone, Eq, PartialEq)]
struct GeneratedItem {
    kid: String,
    index: usize,
}

impl HasKid for GeneratedItem {
    fn kid(&self) -> &str {
        &self.kid
    }
}

proptest! {
    #[test]
    fn build_is_stable_for_arbitrary_kids(
        raw in prop::collection::vec(
            prop::collection::vec(prop::char::range('a'..='z'), 0..8),
            0..64,
        ),
    ) {
        let mut sorter = KidSorted::new();
        let mut expected = Vec::<GeneratedItem>::new();

        for (idx, kid_chars) in raw.iter().enumerate() {
            let kid: String = kid_chars.iter().collect();
            let item = GeneratedItem {
                kid: kid.clone(),
                index: idx,
            };
            sorter.push(item.clone());
            expected.push(item);
        }

        let mut expected = expected;
        expected.sort_by(|a, b| a.kid.cmp(&b.kid).then(a.index.cmp(&b.index)));
        let actual = sorter.build();

        assert_eq!(actual.len(), expected.len());
        for (item, exp) in actual.iter().zip(expected.iter()) {
            assert_eq!(item.kid, exp.kid);
            assert_eq!(item.index, exp.index);
        }
    }
}

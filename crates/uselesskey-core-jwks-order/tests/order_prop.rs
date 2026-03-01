use proptest::prelude::*;
use uselesskey_core_jwks_order::{HasKid, KidSorted};

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

fn kid_vec() -> impl Strategy<Value = Vec<Vec<char>>> {
    prop::collection::vec(
        prop::collection::vec(prop::char::range('a', 'z'), 0..8),
        0..64,
    )
}

fn build_from(raw: &[Vec<char>]) -> (Vec<GeneratedItem>, Vec<GeneratedItem>) {
    let mut sorter = KidSorted::new();
    let mut input = Vec::new();
    for (idx, kid_chars) in raw.iter().enumerate() {
        let kid: String = kid_chars.iter().collect();
        let item = GeneratedItem {
            kid: kid.clone(),
            index: idx,
        };
        sorter.push(item.clone());
        input.push(item);
    }
    (input, sorter.build())
}

proptest! {
    #[test]
    fn build_is_stable_for_arbitrary_kids(raw in kid_vec()) {
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

        expected.sort_by(|a, b| a.kid.cmp(&b.kid).then(a.index.cmp(&b.index)));
        let actual = sorter.build();

        assert_eq!(actual.len(), expected.len());
        for (item, exp) in actual.iter().zip(expected.iter()) {
            assert_eq!(item.kid, exp.kid);
            assert_eq!(item.index, exp.index);
        }
    }

    #[test]
    fn output_length_equals_input(raw in kid_vec()) {
        let (input, output) = build_from(&raw);
        prop_assert_eq!(output.len(), input.len());
    }

    #[test]
    fn output_is_sorted_by_kid(raw in kid_vec()) {
        let (_, output) = build_from(&raw);
        for pair in output.windows(2) {
            prop_assert!(pair[0].kid <= pair[1].kid,
                "not sorted: {:?} > {:?}", pair[0].kid, pair[1].kid);
        }
    }

    #[test]
    fn all_items_preserved(raw in kid_vec()) {
        let (mut input, mut output) = build_from(&raw);
        input.sort_by(|a, b| a.index.cmp(&b.index));
        output.sort_by(|a, b| a.index.cmp(&b.index));
        prop_assert_eq!(input, output);
    }

    #[test]
    fn deterministic_across_builds(raw in kid_vec()) {
        let (_, first) = build_from(&raw);
        let (_, second) = build_from(&raw);
        prop_assert_eq!(first, second);
    }
}

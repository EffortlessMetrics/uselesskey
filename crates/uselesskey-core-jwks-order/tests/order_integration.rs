use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Debug, Clone, Eq, PartialEq)]
struct FixtureItem {
    kid: String,
    marker: usize,
}

impl HasKid for FixtureItem {
    fn kid(&self) -> &str {
        &self.kid
    }
}

#[test]
fn integration_build_orders_deterministic() {
    let mut sorter = KidSorted::new();
    sorter.push(FixtureItem {
        kid: "z-key".to_string(),
        marker: 0,
    });
    sorter.push(FixtureItem {
        kid: "a-key".to_string(),
        marker: 1,
    });
    sorter.push(FixtureItem {
        kid: "m-key".to_string(),
        marker: 2,
    });

    let ordered = sorter.build();
    let kids: Vec<_> = ordered.iter().map(|item| item.kid.as_str()).collect();

    assert_eq!(kids, vec!["a-key", "m-key", "z-key"]);
    assert_eq!(ordered[0].marker, 1);
    assert_eq!(ordered[1].marker, 2);
    assert_eq!(ordered[2].marker, 0);
}

#[test]
fn integration_preserves_insertion_for_duplicate_kids() {
    let mut sorter = KidSorted::new();
    sorter.push(FixtureItem {
        kid: "dup".to_string(),
        marker: 10,
    });
    sorter.push(FixtureItem {
        kid: "dup".to_string(),
        marker: 20,
    });
    sorter.push(FixtureItem {
        kid: "a".to_string(),
        marker: 30,
    });
    sorter.push(FixtureItem {
        kid: "dup".to_string(),
        marker: 40,
    });

    let ordered = sorter.build();
    let dups: Vec<_> = ordered
        .iter()
        .filter(|item| item.kid == "dup")
        .map(|item| item.marker)
        .collect();

    assert_eq!(dups, vec![10, 20, 40]);
}

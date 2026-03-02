//! Mutant-killing tests for KidSorted ordering.

use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Debug, Clone)]
struct Item {
    kid: String,
    data: String,
}

impl HasKid for Item {
    fn kid(&self) -> &str {
        &self.kid
    }
}

fn item(kid: &str, data: &str) -> Item {
    Item {
        kid: kid.to_string(),
        data: data.to_string(),
    }
}

#[test]
fn empty_build_returns_empty() {
    let sorter = KidSorted::<Item>::new();
    assert!(sorter.build().is_empty());
}

#[test]
fn single_item_returns_itself() {
    let mut s = KidSorted::new();
    s.push(item("a", "only"));
    let result = s.build();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].data, "only");
}

#[test]
fn sorts_by_kid_lexicographically() {
    let mut s = KidSorted::new();
    s.push(item("z", "last"));
    s.push(item("a", "first"));
    s.push(item("m", "middle"));

    let result = s.build();
    assert_eq!(result[0].kid, "a");
    assert_eq!(result[1].kid, "m");
    assert_eq!(result[2].kid, "z");
}

#[test]
fn stable_sort_for_equal_kids() {
    let mut s = KidSorted::new();
    s.push(item("dup", "1st"));
    s.push(item("dup", "2nd"));
    s.push(item("dup", "3rd"));

    let result = s.build();
    assert_eq!(result[0].data, "1st");
    assert_eq!(result[1].data, "2nd");
    assert_eq!(result[2].data, "3rd");
}

#[test]
fn mixed_kids_with_ties() {
    let mut s = KidSorted::new();
    s.push(item("b", "b1"));
    s.push(item("a", "a1"));
    s.push(item("b", "b2"));
    s.push(item("a", "a2"));

    let result = s.build();
    assert_eq!(result[0].data, "a1");
    assert_eq!(result[1].data, "a2");
    assert_eq!(result[2].data, "b1");
    assert_eq!(result[3].data, "b2");
}

#[test]
fn debug_shows_entry_count() {
    let mut s = KidSorted::new();
    s.push(item("a", "x"));
    s.push(item("b", "y"));
    let dbg = format!("{s:?}");
    assert!(dbg.contains("KidSorted"));
    assert!(dbg.contains("2"));
}

#[test]
fn default_is_empty() {
    let s = KidSorted::<Item>::default();
    assert!(s.build().is_empty());
}

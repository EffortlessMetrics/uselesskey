//! Integration tests for KidSorted — edge cases, Debug format, and
//! Default trait behavior.

use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Debug, Clone, Eq, PartialEq)]
struct Item {
    kid: String,
    seq: usize,
}

impl HasKid for Item {
    fn kid(&self) -> &str {
        &self.kid
    }
}

fn item(kid: &str, seq: usize) -> Item {
    Item {
        kid: kid.to_string(),
        seq,
    }
}

// ── empty collection ─────────────────────────────────────────────────

#[test]
fn empty_build_returns_empty_vec() {
    let sorter = KidSorted::<Item>::new();
    let result = sorter.build();
    assert!(result.is_empty());
}

// ── single item ──────────────────────────────────────────────────────

#[test]
fn single_item_build_returns_that_item() {
    let mut sorter = KidSorted::new();
    sorter.push(item("only", 1));
    let result = sorter.build();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].kid, "only");
}

// ── lexicographic ordering ───────────────────────────────────────────

#[test]
fn sorts_lexicographically_by_kid() {
    let mut sorter = KidSorted::new();
    sorter.push(item("charlie", 0));
    sorter.push(item("alpha", 1));
    sorter.push(item("bravo", 2));

    let result = sorter.build();
    let kids: Vec<&str> = result.iter().map(|i| i.kid.as_str()).collect();
    assert_eq!(kids, vec!["alpha", "bravo", "charlie"]);
}

#[test]
fn numeric_kids_sort_lexicographically_not_numerically() {
    let mut sorter = KidSorted::new();
    sorter.push(item("9", 0));
    sorter.push(item("10", 1));
    sorter.push(item("2", 2));

    let result = sorter.build();
    let kids: Vec<&str> = result.iter().map(|i| i.kid.as_str()).collect();
    // Lexicographic: "10" < "2" < "9"
    assert_eq!(kids, vec!["10", "2", "9"]);
}

// ── stable tie-breaking ──────────────────────────────────────────────

#[test]
fn duplicate_kids_preserve_insertion_order() {
    let mut sorter = KidSorted::new();
    sorter.push(item("dup", 1));
    sorter.push(item("dup", 2));
    sorter.push(item("dup", 3));

    let result = sorter.build();
    let seqs: Vec<usize> = result.iter().map(|i| i.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
}

#[test]
fn mixed_unique_and_duplicate_kids() {
    let mut sorter = KidSorted::new();
    sorter.push(item("b", 1));
    sorter.push(item("a", 2));
    sorter.push(item("b", 3));
    sorter.push(item("a", 4));

    let result = sorter.build();
    let kids: Vec<(&str, usize)> = result.iter().map(|i| (i.kid.as_str(), i.seq)).collect();
    assert_eq!(kids, vec![("a", 2), ("a", 4), ("b", 1), ("b", 3)]);
}

// ── unicode kids ─────────────────────────────────────────────────────

#[test]
fn unicode_kids_sort_by_byte_order() {
    let mut sorter = KidSorted::new();
    sorter.push(item("ñ", 0));
    sorter.push(item("a", 1));
    sorter.push(item("z", 2));

    let result = sorter.build();
    // 'a' < 'z' < 'ñ' (ñ is multi-byte UTF-8: 0xC3 0xB1)
    let kids: Vec<&str> = result.iter().map(|i| i.kid.as_str()).collect();
    assert_eq!(kids, vec!["a", "z", "ñ"]);
}

// ── empty string kid ─────────────────────────────────────────────────

#[test]
fn empty_kid_sorts_first() {
    let mut sorter = KidSorted::new();
    sorter.push(item("z", 0));
    sorter.push(item("", 1));
    sorter.push(item("a", 2));

    let result = sorter.build();
    let kids: Vec<&str> = result.iter().map(|i| i.kid.as_str()).collect();
    assert_eq!(kids, vec!["", "a", "z"]);
}

// ── Debug format ─────────────────────────────────────────────────────

#[test]
fn debug_shows_entry_count() {
    let mut sorter = KidSorted::new();
    sorter.push(item("a", 1));
    sorter.push(item("b", 2));

    let dbg = format!("{sorter:?}");
    assert!(dbg.contains("KidSorted"));
    assert!(dbg.contains("2"));
}

// ── Default trait ────────────────────────────────────────────────────

#[test]
fn default_creates_empty_sorter() {
    let sorter = KidSorted::<Item>::default();
    let result = sorter.build();
    assert!(result.is_empty());
}

// ── large collection ─────────────────────────────────────────────────

#[test]
fn large_collection_sorts_correctly() {
    let mut sorter = KidSorted::new();
    for i in (0..100).rev() {
        sorter.push(item(&format!("{i:03}"), i));
    }

    let result = sorter.build();
    for (i, item) in result.iter().enumerate() {
        assert_eq!(item.kid, format!("{i:03}"));
    }
}

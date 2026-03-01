//! Comprehensive tests for the `uselesskey-core-jwks-order` crate.

use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Debug, Clone, Eq, PartialEq)]
struct Item {
    kid: String,
    tag: &'static str,
}

impl HasKid for Item {
    fn kid(&self) -> &str {
        &self.kid
    }
}

fn item(kid: &str, tag: &'static str) -> Item {
    Item {
        kid: kid.to_string(),
        tag,
    }
}

// ---------------------------------------------------------------------------
// 1. Deterministic ordering
// ---------------------------------------------------------------------------

#[test]
fn ordering_is_deterministic_across_runs() {
    let run = || {
        let mut s = KidSorted::new();
        s.push(item("charlie", "c"));
        s.push(item("alpha", "a"));
        s.push(item("bravo", "b"));
        s.build()
    };

    let first = run();
    let second = run();
    assert_eq!(first, second);
}

// ---------------------------------------------------------------------------
// 2. Different insertion orders produce same sorted output
// ---------------------------------------------------------------------------

#[test]
fn insertion_order_does_not_affect_sorted_result() {
    let mut s1 = KidSorted::new();
    s1.push(item("z", "last"));
    s1.push(item("a", "first"));
    s1.push(item("m", "middle"));

    let mut s2 = KidSorted::new();
    s2.push(item("a", "first"));
    s2.push(item("m", "middle"));
    s2.push(item("z", "last"));

    let mut s3 = KidSorted::new();
    s3.push(item("m", "middle"));
    s3.push(item("z", "last"));
    s3.push(item("a", "first"));

    let r1 = s1.build();
    let r2 = s2.build();
    let r3 = s3.build();

    assert_eq!(r1, r2);
    assert_eq!(r2, r3);

    let kids: Vec<_> = r1.iter().map(|i| i.kid.as_str()).collect();
    assert_eq!(kids, vec!["a", "m", "z"]);
}

// ---------------------------------------------------------------------------
// 3. Empty collection
// ---------------------------------------------------------------------------

#[test]
fn empty_collection_builds_empty_vec() {
    let s = KidSorted::<Item>::new();
    let result = s.build();
    assert!(result.is_empty());
}

#[test]
fn default_is_empty() {
    let s = KidSorted::<Item>::default();
    assert!(s.build().is_empty());
}

// ---------------------------------------------------------------------------
// 4. Single key
// ---------------------------------------------------------------------------

#[test]
fn single_item_builds_one_element_vec() {
    let mut s = KidSorted::new();
    s.push(item("only", "sole"));
    let result = s.build();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].kid, "only");
    assert_eq!(result[0].tag, "sole");
}

// ---------------------------------------------------------------------------
// 5. Stable tie-breaking on insertion order
// ---------------------------------------------------------------------------

#[test]
fn duplicate_kids_preserve_insertion_order() {
    let mut s = KidSorted::new();
    s.push(item("same", "first"));
    s.push(item("same", "second"));
    s.push(item("same", "third"));

    let result = s.build();
    let tags: Vec<_> = result.iter().map(|i| i.tag).collect();
    assert_eq!(tags, vec!["first", "second", "third"]);
}

#[test]
fn mixed_unique_and_duplicate_kids() {
    let mut s = KidSorted::new();
    s.push(item("b", "b1"));
    s.push(item("a", "a1"));
    s.push(item("b", "b2"));
    s.push(item("a", "a2"));

    let result = s.build();
    let out: Vec<_> = result.iter().map(|i| (i.kid.as_str(), i.tag)).collect();
    assert_eq!(
        out,
        vec![("a", "a1"), ("a", "a2"), ("b", "b1"), ("b", "b2")]
    );
}

// ---------------------------------------------------------------------------
// 6. Debug format
// ---------------------------------------------------------------------------

#[test]
fn debug_shows_entry_count() {
    let mut s = KidSorted::new();
    s.push(item("x", "a"));
    s.push(item("y", "b"));
    let dbg = format!("{s:?}");
    assert!(dbg.contains("KidSorted"));
    assert!(dbg.contains("2"), "should show entry count");
}

// ---------------------------------------------------------------------------
// 7. Clone
// ---------------------------------------------------------------------------

#[test]
fn clone_produces_independent_copy() {
    let mut s = KidSorted::new();
    s.push(item("a", "orig"));
    let s2 = s.clone();

    let r1 = s.build();
    let r2 = s2.build();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// 8. Lexicographic ordering
// ---------------------------------------------------------------------------

#[test]
fn numeric_kid_sorts_lexicographically() {
    let mut s = KidSorted::new();
    s.push(item("10", "ten"));
    s.push(item("2", "two"));
    s.push(item("1", "one"));

    let result = s.build();
    let kids: Vec<_> = result.iter().map(|i| i.kid.as_str()).collect();
    // Lexicographic: "1" < "10" < "2"
    assert_eq!(kids, vec!["1", "10", "2"]);
}

#[test]
fn case_sensitive_ordering() {
    let mut s = KidSorted::new();
    s.push(item("b", "lower-b"));
    s.push(item("A", "upper-a"));
    s.push(item("a", "lower-a"));

    let result = s.build();
    let kids: Vec<_> = result.iter().map(|i| i.kid.as_str()).collect();
    // ASCII: 'A' (65) < 'a' (97) < 'b' (98)
    assert_eq!(kids, vec!["A", "a", "b"]);
}

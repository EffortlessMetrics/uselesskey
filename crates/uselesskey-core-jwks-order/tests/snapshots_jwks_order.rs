//! Insta snapshot tests for uselesskey-core-jwks-order.
//!
//! Snapshot KidSorted ordering semantics.

use serde::Serialize;
use uselesskey_core_jwks_order::{HasKid, KidSorted};

#[derive(Clone)]
struct Item {
    kid: String,
    tag: String,
}

impl HasKid for Item {
    fn kid(&self) -> &str {
        &self.kid
    }
}

fn item(kid: &str, tag: &str) -> Item {
    Item {
        kid: kid.into(),
        tag: tag.into(),
    }
}

#[derive(Serialize)]
struct OrderResult {
    kids: Vec<String>,
    tags: Vec<String>,
}

fn build_result(items: Vec<Item>) -> OrderResult {
    let mut sorter = KidSorted::new();
    for i in items {
        sorter.push(i);
    }
    let sorted = sorter.build();
    OrderResult {
        kids: sorted.iter().map(|i| i.kid.clone()).collect(),
        tags: sorted.iter().map(|i| i.tag.clone()).collect(),
    }
}

#[test]
fn snapshot_lexicographic_sort() {
    let result = build_result(vec![
        item("charlie", "c"),
        item("alpha", "a"),
        item("bravo", "b"),
    ]);
    insta::assert_yaml_snapshot!("kid_sorted_lexicographic", result);
}

#[test]
fn snapshot_stable_tie_breaking() {
    let result = build_result(vec![
        item("dup", "first"),
        item("dup", "second"),
        item("dup", "third"),
    ]);
    insta::assert_yaml_snapshot!("kid_sorted_stable_ties", result);
}

#[test]
fn snapshot_mixed_duplicates_and_unique() {
    let result = build_result(vec![
        item("z", "z1"),
        item("a", "a1"),
        item("m", "m1"),
        item("a", "a2"),
        item("z", "z2"),
    ]);
    insta::assert_yaml_snapshot!("kid_sorted_mixed", result);
}

#[test]
fn snapshot_single_item() {
    let result = build_result(vec![item("only", "single")]);
    insta::assert_yaml_snapshot!("kid_sorted_single", result);
}

#[test]
fn snapshot_empty() {
    let result = build_result(vec![]);
    insta::assert_yaml_snapshot!("kid_sorted_empty", result);
}

#[test]
fn snapshot_already_sorted() {
    let result = build_result(vec![item("a", "1"), item("b", "2"), item("c", "3")]);
    insta::assert_yaml_snapshot!("kid_sorted_already_sorted", result);
}

#[test]
fn snapshot_reverse_order() {
    let result = build_result(vec![item("c", "3"), item("b", "2"), item("a", "1")]);
    insta::assert_yaml_snapshot!("kid_sorted_reverse", result);
}

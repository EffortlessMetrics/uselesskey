#![forbid(unsafe_code)]

use core::fmt;

/// A minimal trait for items with a stable key-id used for ordering.
pub trait HasKid {
    /// Return the sort key for the item.
    fn kid(&self) -> &str;
}

/// Store items and return them sorted by `kid` with deterministic
/// tie-breakers based on insertion order.
#[derive(Clone)]
pub struct KidSorted<T: HasKid> {
    entries: Vec<Entry<T>>,
}

impl<T: HasKid> Default for KidSorted<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct Entry<T: HasKid> {
    kid: String,
    index: usize,
    value: T,
}

impl<T: HasKid + fmt::Debug> fmt::Debug for KidSorted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KidSorted")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<T: HasKid> KidSorted<T> {
    /// Construct an empty ordered collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a value into the collection.
    pub fn push(&mut self, value: T) {
        let index = self.entries.len();
        let kid = value.kid().to_string();
        self.entries.push(Entry { kid, index, value });
    }

    /// Build the final vector, sorted by `kid`, stable on insertion order.
    pub fn build(mut self) -> Vec<T> {
        self.entries
            .sort_by(|a, b| a.kid.cmp(&b.kid).then(a.index.cmp(&b.index)));
        self.entries.into_iter().map(|e| e.value).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{HasKid, KidSorted};

    #[derive(Debug, Clone)]
    struct TestItem {
        kid: &'static str,
        payload: &'static str,
    }

    impl HasKid for TestItem {
        fn kid(&self) -> &str {
            self.kid
        }
    }

    #[test]
    fn orders_items_by_kid() {
        let mut sorter = KidSorted::new();
        sorter.push(TestItem {
            kid: "b",
            payload: "second",
        });
        sorter.push(TestItem {
            kid: "a",
            payload: "first",
        });
        let items = sorter.build();
        let order: Vec<_> = items.iter().map(|item| item.payload).collect();

        assert_eq!(order, vec!["first", "second"]);
    }

    #[test]
    fn preserves_insertion_for_equal_kids() {
        let mut sorter = KidSorted::new();
        sorter.push(TestItem {
            kid: "dup",
            payload: "one",
        });
        sorter.push(TestItem {
            kid: "dup",
            payload: "two",
        });
        sorter.push(TestItem {
            kid: "dup",
            payload: "three",
        });

        let items = sorter.build();
        let order: Vec<_> = items.iter().map(|item| item.payload).collect();

        assert_eq!(order, vec!["one", "two", "three"]);
    }
}

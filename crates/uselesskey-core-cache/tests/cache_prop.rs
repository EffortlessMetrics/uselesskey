use std::sync::Arc;

use proptest::prelude::*;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, b"spec", variant, DerivationVersion::V1)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Same key always retrieves the same cached value.
    #[test]
    fn same_key_returns_same_value(
        label in "[a-zA-Z0-9]{1,16}",
        value in any::<u64>(),
    ) {
        let cache = ArtifactCache::new();
        let id = make_id("domain:prop", &label, "good");

        let first = cache.insert_if_absent_typed(id.clone(), Arc::new(value));
        let second = cache.get_typed::<u64>(&id).expect("should be cached");

        prop_assert_eq!(*first, value);
        prop_assert!(Arc::ptr_eq(&first, &second));
    }

    /// Different labels produce independent cache entries.
    #[test]
    fn different_labels_are_independent(
        label1 in "[a-zA-Z0-9]{1,16}",
        label2 in "[a-zA-Z0-9]{1,16}",
        v1 in any::<u32>(),
        v2 in any::<u32>(),
    ) {
        prop_assume!(label1 != label2);

        let cache = ArtifactCache::new();
        let id1 = make_id("domain:prop", &label1, "good");
        let id2 = make_id("domain:prop", &label2, "good");

        cache.insert_if_absent_typed(id1.clone(), Arc::new(v1));
        cache.insert_if_absent_typed(id2.clone(), Arc::new(v2));

        let got1 = cache.get_typed::<u32>(&id1).expect("id1 should exist");
        let got2 = cache.get_typed::<u32>(&id2).expect("id2 should exist");

        prop_assert_eq!(*got1, v1);
        prop_assert_eq!(*got2, v2);
    }

    /// Clearing the cache empties all entries, and re-insert creates fresh values.
    #[test]
    fn clear_resets_state(
        label in "[a-zA-Z0-9]{1,16}",
        v1 in any::<u32>(),
        v2 in any::<u32>(),
    ) {
        let cache = ArtifactCache::new();
        let id = make_id("domain:prop", &label, "good");

        let before = cache.insert_if_absent_typed(id.clone(), Arc::new(v1));
        prop_assert_eq!(cache.len(), 1);

        cache.clear();
        prop_assert!(cache.is_empty());
        prop_assert!(cache.get_typed::<u32>(&id).is_none());

        let after = cache.insert_if_absent_typed(id, Arc::new(v2));
        prop_assert_eq!(*after, v2);
        // After clear + re-insert, the Arc identity must differ from the original.
        prop_assert!(!Arc::ptr_eq(&before, &after));
    }

    /// insert_if_absent_typed keeps the first value, ignoring subsequent inserts.
    #[test]
    fn insert_if_absent_keeps_first(
        label in "[a-zA-Z0-9]{1,16}",
        v1 in any::<u64>(),
        v2 in any::<u64>(),
    ) {
        let cache = ArtifactCache::new();
        let id = make_id("domain:prop", &label, "good");

        let first = cache.insert_if_absent_typed(id.clone(), Arc::new(v1));
        let second = cache.insert_if_absent_typed(id, Arc::new(v2));

        prop_assert!(Arc::ptr_eq(&first, &second));
        prop_assert_eq!(*second, v1);
    }
}

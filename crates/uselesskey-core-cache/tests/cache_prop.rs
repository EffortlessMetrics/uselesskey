use std::sync::Arc;

use proptest::prelude::*;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(
        "domain:prop",
        label,
        b"spec",
        variant,
        DerivationVersion::V1,
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Inserting and retrieving a typed value round-trips correctly.
    #[test]
    fn insert_and_get_round_trip(label in "[a-z]{1,16}", value in any::<u64>()) {
        let cache = ArtifactCache::new();
        let id = make_id(&label, "default");

        let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(value));
        let fetched = cache.get_typed::<u64>(&id).expect("value should be present");

        prop_assert_eq!(*inserted, value);
        prop_assert_eq!(*fetched, value);
    }

    /// insert_if_absent_typed always returns the first inserted value.
    #[test]
    fn first_value_wins(
        label in "[a-z]{1,16}",
        first in any::<u64>(),
        second in any::<u64>(),
    ) {
        let cache = ArtifactCache::new();
        let id = make_id(&label, "default");

        let winner = cache.insert_if_absent_typed(id.clone(), Arc::new(first));
        let again = cache.insert_if_absent_typed(id, Arc::new(second));

        prop_assert_eq!(*winner, first);
        prop_assert_eq!(*again, first);
    }

    /// Distinct labels produce distinct cache entries.
    #[test]
    fn distinct_labels_no_collision(
        label_a in "[a-z]{1,8}",
        label_b in "[a-z]{1,8}",
    ) {
        prop_assume!(label_a != label_b);
        let cache = ArtifactCache::new();

        let id_a = make_id(&label_a, "default");
        let id_b = make_id(&label_b, "default");

        cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
        cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

        prop_assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1u32);
        prop_assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2u32);
        prop_assert_eq!(cache.len(), 2);
    }

    /// Cache len tracks insertions correctly.
    #[test]
    fn len_tracks_insertions(count in 1usize..=20) {
        let cache = ArtifactCache::new();
        for i in 0..count {
            let id = make_id(&format!("label-{i}"), "default");
            cache.insert_if_absent_typed(id, Arc::new(i as u64));
        }
        prop_assert_eq!(cache.len(), count);
        prop_assert!(!cache.is_empty());
    }

    /// clear() empties the cache.
    #[test]
    fn clear_empties(count in 1usize..=10) {
        let cache = ArtifactCache::new();
        for i in 0..count {
            let id = make_id(&format!("label-{i}"), "default");
            cache.insert_if_absent_typed(id, Arc::new(i as u64));
        }
        cache.clear();
        prop_assert!(cache.is_empty());
        prop_assert_eq!(cache.len(), 0);
    }
}

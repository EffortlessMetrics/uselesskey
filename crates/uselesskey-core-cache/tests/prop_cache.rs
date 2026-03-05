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
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn insert_get_roundtrip(label in "[a-z]{1,16}", value in any::<u64>()) {
        let cache = ArtifactCache::new();
        let id = make_id(&label, "good");

        cache.insert_if_absent_typed(id.clone(), Arc::new(value));
        let got = cache.get_typed::<u64>(&id).unwrap();
        prop_assert_eq!(*got, value);
    }

    #[test]
    fn insert_if_absent_keeps_first(label in "[a-z]{1,8}", v1 in any::<u32>(), v2 in any::<u32>()) {
        let cache = ArtifactCache::new();
        let id = make_id(&label, "good");

        let first = cache.insert_if_absent_typed(id.clone(), Arc::new(v1));
        let second = cache.insert_if_absent_typed(id.clone(), Arc::new(v2));
        prop_assert!(Arc::ptr_eq(&first, &second));
        prop_assert_eq!(*first, v1);
    }

    #[test]
    fn distinct_labels_stored_independently(
        label_a in "[a-z]{1,8}",
        label_b in "[a-z]{1,8}",
        va in any::<u32>(),
        vb in any::<u32>(),
    ) {
        prop_assume!(label_a != label_b);
        let cache = ArtifactCache::new();
        let id_a = make_id(&label_a, "good");
        let id_b = make_id(&label_b, "good");

        cache.insert_if_absent_typed(id_a.clone(), Arc::new(va));
        cache.insert_if_absent_typed(id_b.clone(), Arc::new(vb));

        prop_assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), va);
        prop_assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), vb);
        prop_assert_eq!(cache.len(), 2);
    }

    #[test]
    fn len_matches_distinct_inserts(count in 1usize..32) {
        let cache = ArtifactCache::new();
        for i in 0..count {
            let id = make_id(&format!("k{i}"), "good");
            cache.insert_if_absent_typed(id, Arc::new(i as u32));
        }
        prop_assert_eq!(cache.len(), count);
    }

    #[test]
    fn clear_always_empties(count in 1usize..32) {
        let cache = ArtifactCache::new();
        for i in 0..count {
            let id = make_id(&format!("k{i}"), "good");
            cache.insert_if_absent_typed(id, Arc::new(i as u32));
        }
        cache.clear();
        prop_assert!(cache.is_empty());
        prop_assert_eq!(cache.len(), 0);
    }

    #[test]
    fn get_absent_key_returns_none(label in "[a-z]{1,16}") {
        let cache = ArtifactCache::new();
        let id = make_id(&label, "good");
        prop_assert!(cache.get_typed::<u32>(&id).is_none());
    }

    #[test]
    fn distinct_variants_stored_independently(
        label in "[a-z]{1,8}",
        variant_a in "[a-z]{1,8}",
        variant_b in "[a-z]{1,8}",
    ) {
        prop_assume!(variant_a != variant_b);
        let cache = ArtifactCache::new();
        let id_a = make_id(&label, &variant_a);
        let id_b = make_id(&label, &variant_b);

        cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
        cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

        prop_assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1);
        prop_assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2);
    }
}

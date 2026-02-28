#![no_main]

use libfuzzer_sys::fuzz_target;

use std::sync::Arc;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fuzz_target!(|data: &[u8]| {
    let cache = ArtifactCache::new();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    // Build a few artifact IDs from fuzz input.
    let chunks: Vec<&[u8]> = data.chunks(8).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let label = format!("label-{i}");
        let id = ArtifactId::new("fuzz", &label, chunk, "default", DerivationVersion::V1);

        let value: Arc<u64> = Arc::new(i as u64);
        let inserted = cache.insert_if_absent_typed(id.clone(), value);
        assert_eq!(*inserted, i as u64);

        // Second insert returns the cached value.
        let again = cache.insert_if_absent_typed(id.clone(), Arc::new(999u64));
        assert_eq!(*again, i as u64);

        // get_typed round-trips.
        let got = cache.get_typed::<u64>(&id);
        assert!(got.is_some());
        assert_eq!(*got.unwrap(), i as u64);
    }

    let len_before = cache.len();
    assert_eq!(len_before, chunks.len());

    // Clear and verify empty.
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    // Re-insert after clear should succeed with new value.
    if !chunks.is_empty() {
        let id = ArtifactId::new("fuzz", "label-0", chunks[0], "default", DerivationVersion::V1);
        let fresh = cache.insert_if_absent_typed(id.clone(), Arc::new(42u64));
        assert_eq!(*fresh, 42u64);
    }
});

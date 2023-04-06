use crate::beacon_chain::BeaconStore;
use crate::BeaconChainTypes;
use lru::LruCache;

pub struct OverflowLRUCache<T: BeaconChainTypes, Key, Value> {
    in_memory: LruCache<Key, Value>,
    store: BeaconStore<T>,
    key: u64,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cache_added_entries_exist() {
        let mut cache = LRUTimeCache::new(Duration::from_secs(10));

        cache.insert("t");
        cache.insert("e");

        // Should report that 't' and 't' already exists
        assert!(!cache.insert("t"));
        assert!(!cache.insert("e"));
    }

    #[test]
    fn test_reinsertion_updates_timeout() {
        let mut cache = LRUTimeCache::new(Duration::from_millis(100));

        cache.insert("a");
        cache.insert("b");

        std::thread::sleep(Duration::from_millis(20));
        cache.insert("a");
        // a is newer now

        std::thread::sleep(Duration::from_millis(85));
        assert!(cache.contains(&"a"),);
        // b was inserted first but was not as recent it should have been removed
        assert!(!cache.contains(&"b"));

        std::thread::sleep(Duration::from_millis(16));
        assert!(!cache.contains(&"a"));
    }
}

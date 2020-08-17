///! This implements a time-based LRU cache for fast checking of duplicates
use fnv::FnvHashSet;
use std::collections::VecDeque;

/// Cache that stores keys until the size is used up. Does not update elements for efficiency.
pub struct LRUCache<Key>
where
    Key: Eq + std::hash::Hash + Clone,
{
    /// The duplicate cache.
    map: FnvHashSet<Key>,
    /// An ordered list of keys by order.
    list: VecDeque<Key>,
    // The max size of the cache,
    size: usize,
}

impl<Key> LRUCache<Key>
where
    Key: Eq + std::hash::Hash + Clone,
{
    pub fn new(size: usize) -> Self {
        LRUCache {
            map: FnvHashSet::default(),
            list: VecDeque::new(),
            size,
        }
    }

    /// Determines if the key is in the cache.
    pub fn contains(&self, key: &Key) -> bool {
        self.map.contains(key)
    }

    // Inserts new elements and removes any expired elements.
    //
    // If the key was not present this returns `true`. If the value was already present this
    // returns `false`.
    pub fn insert(&mut self, key: Key) -> bool {
        // check the cache before removing elements
        let result = self.map.insert(key.clone());

        // add the new key to the list, if it doesn't already exist.
        if result {
            self.list.push_back(key);
        }
        // remove any overflow keys
        self.update();
        result
    }

    /// Removes any expired elements from the cache.
    fn update(&mut self) {
        // remove any expired results
        for _ in 0..self.map.len().saturating_sub(self.size) {
            if let Some(key) = self.list.pop_front() {
                self.map.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cache_added_entries_exist() {
        let mut cache = LRUCache::new(5);

        cache.insert("t");
        cache.insert("e");

        // Should report that 't' and 't' already exists
        assert!(!cache.insert("t"));
        assert!(!cache.insert("e"));
    }

    #[test]
    fn cache_entries_get_removed() {
        let mut cache = LRUCache::new(2);

        cache.insert("t");
        assert!(!cache.insert("t"));
        cache.insert("e");
        assert!(!cache.insert("e"));
        // add another element to clear the first key
        cache.insert("s");
        assert!(!cache.insert("s"));
        // should be removed from the cache
        assert!(cache.insert("t"));
    }
}

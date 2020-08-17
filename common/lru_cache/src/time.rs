///! This implements a time-based LRU cache for fast checking of duplicates
use fnv::FnvHashSet;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

struct Element<Key> {
    /// The key being inserted.
    key: Key,
    /// The instant the key was inserted.
    inserted: Instant,
}

pub struct LRUTimeCache<Key> {
    /// The duplicate cache.
    map: FnvHashSet<Key>,
    /// An ordered list of keys by insert time.
    list: VecDeque<Element<Key>>,
    /// The time elements remain in the cache.
    ttl: Duration,
}

impl<Key> LRUTimeCache<Key>
where
    Key: Eq + std::hash::Hash + Clone,
{
    pub fn new(ttl: Duration) -> Self {
        LRUTimeCache {
            map: FnvHashSet::default(),
            list: VecDeque::new(),
            ttl,
        }
    }

    // Inserts new elements and removes any expired elements.
    //
    // If the key was not present this returns `true`. If the value was already present this
    // returns `false`.
    pub fn insert_update(&mut self, key: Key) -> bool {
        // check the cache before removing elements
        let result = self.map.insert(key.clone());

        let now = Instant::now();

        // remove any expired results
        while let Some(element) = self.list.pop_front() {
            if element.inserted + self.ttl > now {
                self.list.push_front(element);
                break;
            }
            self.map.remove(&element.key);
        }

        // add the new key to the list, if it doesn't already exist.
        if result {
            self.list.push_back(Element { key, inserted: now });
        }

        result
    }

    // Inserts new element does not expire old elements.
    //
    // If the key was not present this returns `true`. If the value was already present this
    // returns `false`.
    pub fn insert(&mut self, key: Key) -> bool {
        // check the cache before removing elements
        let result = self.map.insert(key.clone());

        // add the new key to the list, if it doesn't already exist.
        if result {
            self.list.push_back(Element {
                key,
                inserted: Instant::now(),
            });
        }
        result
    }

    /// Removes any expired elements from the cache.
    pub fn update(&mut self) {
        let now = Instant::now();
        // remove any expired results
        while let Some(element) = self.list.pop_front() {
            if element.inserted + self.ttl > now {
                self.list.push_front(element);
                break;
            }
            self.map.remove(&element.key);
        }
    }
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
    fn cache_entries_expire() {
        let mut cache = LRUTimeCache::new(Duration::from_millis(100));

        cache.insert_update("t");
        assert!(!cache.insert_update("t"));
        cache.insert_update("e");
        assert!(!cache.insert_update("t"));
        assert!(!cache.insert_update("e"));
        // sleep until cache expiry
        std::thread::sleep(Duration::from_millis(101));
        // add another element to clear previous cache
        cache.insert_update("s");

        // should be removed from the cache
        assert!(cache.insert_update("t"));
    }
}

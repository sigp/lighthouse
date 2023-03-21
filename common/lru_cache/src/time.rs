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

    /// Inserts a key without removal of potentially expired elements.
    /// Returns true if the key does not already exist.
    pub fn raw_insert(&mut self, key: Key) -> bool {
        // check the cache before removing elements
        let is_new = self.map.insert(key.clone());

        // add the new key to the list, if it doesn't already exist.
        if is_new {
            self.list.push_back(Element {
                key,
                inserted: Instant::now(),
            });
        } else {
            let position = self
                .list
                .iter()
                .position(|e| e.key == key)
                .expect("Key is not new");
            let mut element = self
                .list
                .remove(position)
                .expect("Position is not occupied");
            element.inserted = Instant::now();
            self.list.push_back(element);
        }
        #[cfg(test)]
        self.check_invariant();
        is_new
    }

    /// Removes a key from the cache without purging expired elements. Returns true if the key
    /// existed.
    pub fn raw_remove(&mut self, key: &Key) -> bool {
        if self.map.remove(key) {
            let position = self
                .list
                .iter()
                .position(|e| &e.key == key)
                .expect("Key must exist");
            self.list
                .remove(position)
                .expect("Position is not occupied");
            true
        } else {
            false
        }
    }

    /// Removes all expired elements and returns them
    pub fn remove_expired(&mut self) -> Vec<Key> {
        if self.list.is_empty() {
            return Vec::new();
        }

        let mut removed_elements = Vec::new();
        let now = Instant::now();
        // remove any expired results
        while let Some(element) = self.list.pop_front() {
            if element.inserted + self.ttl > now {
                self.list.push_front(element);
                break;
            }
            self.map.remove(&element.key);
            removed_elements.push(element.key);
        }
        #[cfg(test)]
        self.check_invariant();

        removed_elements
    }

    // Inserts a new key. It first purges expired elements to do so.
    //
    // If the key was not present this returns `true`. If the value was already present this
    // returns `false` and updates the insertion time of the key.
    pub fn insert(&mut self, key: Key) -> bool {
        self.update();
        // check the cache before removing elements
        let is_new = self.map.insert(key.clone());

        // add the new key to the list, if it doesn't already exist.
        if is_new {
            self.list.push_back(Element {
                key,
                inserted: Instant::now(),
            });
        } else {
            let position = self
                .list
                .iter()
                .position(|e| e.key == key)
                .expect("Key is not new");
            let mut element = self
                .list
                .remove(position)
                .expect("Position is not occupied");
            element.inserted = Instant::now();
            self.list.push_back(element);
        }
        #[cfg(test)]
        self.check_invariant();
        is_new
    }

    /// Removes any expired elements from the cache.
    pub fn update(&mut self) {
        if self.list.is_empty() {
            return;
        }

        let now = Instant::now();
        // remove any expired results
        while let Some(element) = self.list.pop_front() {
            if element.inserted + self.ttl > now {
                self.list.push_front(element);
                break;
            }
            self.map.remove(&element.key);
        }
        #[cfg(test)]
        self.check_invariant()
    }

    /// Returns if the key is present after removing expired elements.
    pub fn contains(&mut self, key: &Key) -> bool {
        self.update();
        self.map.contains(key)
    }

    #[cfg(test)]
    #[track_caller]
    fn check_invariant(&self) {
        // The list should be sorted. First element should have the oldest insertion
        let mut prev_insertion_time = None;
        for e in &self.list {
            match prev_insertion_time {
                Some(prev) => {
                    if prev <= e.inserted {
                        prev_insertion_time = Some(e.inserted);
                    } else {
                        panic!("List is not sorted by insertion time")
                    }
                }
                None => prev_insertion_time = Some(e.inserted),
            }
            // The key should be in the map
            assert!(self.map.contains(&e.key), "List and map should be in sync");
        }

        for k in &self.map {
            let _ = self
                .list
                .iter()
                .position(|e| &e.key == k)
                .expect("Map and list should be in sync");
        }

        // One last check to make sure there are no duplicates in the list
        assert_eq!(self.list.len(), self.map.len());
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

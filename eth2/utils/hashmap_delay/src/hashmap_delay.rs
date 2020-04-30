//! A simple hashmap object coupled with a `delay_queue` which has entries that expire after a
//! fixed time.
//!
//! A `HashMapDelay` implements `Stream` which removes expired items from the map.

/// The default delay for entries, in seconds. This is only used when `insert()` is used to add
/// entries.
const DEFAULT_DELAY: u64 = 30;

use futures::prelude::*;
use std::collections::HashMap;
use std::time::Duration;
use tokio_timer::delay_queue::{self, DelayQueue};

pub struct HashMapDelay<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone,
{
    /// The given entries.
    entries: HashMap<K, MapEntry<V>>,
    /// A queue holding the timeouts of each entry.
    expirations: DelayQueue<K>,
    /// The default expiration timeout of an entry.
    default_entry_timeout: Duration,
}

/// A wrapping around entries that adds the link to the entry's expiration, via a `delay_queue` key.
struct MapEntry<V> {
    /// The expiration key for the entry.
    key: delay_queue::Key,
    /// The actual entry.
    value: V,
}

impl<K, V> Default for HashMapDelay<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone,
{
    fn default() -> Self {
        HashMapDelay::new(Duration::from_secs(DEFAULT_DELAY))
    }
}

impl<K, V> HashMapDelay<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone,
{
    /// Creates a new instance of `HashMapDelay`.
    pub fn new(default_entry_timeout: Duration) -> Self {
        HashMapDelay {
            entries: HashMap::new(),
            expirations: DelayQueue::new(),
            default_entry_timeout,
        }
    }

    /// Insert an entry into the mapping. Entries will expire after the `default_entry_timeout`.
    pub fn insert(&mut self, key: K, value: V) {
        self.insert_at(key, value, self.default_entry_timeout);
    }

    /// Inserts an entry that will expire at a given instant.
    pub fn insert_at(&mut self, key: K, value: V, entry_duration: Duration) {
        let delay_key = self.expirations.insert(key.clone(), entry_duration);
        let entry = MapEntry {
            key: delay_key,
            value,
        };
        self.entries.insert(key, entry);
    }

    /// Gets a reference to an entry if it exists.
    ///
    /// Returns None if the entry does not exist.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    /// Gets a mutable reference to an entry if it exists.
    ///
    /// Returns None if the entry does not exist.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    /// Returns true if the key exists, false otherwise.
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the length of the mapping.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Updates the timeout for a given key. Returns true if the key existed, false otherwise.
    ///
    /// Panics if the duration is too far in the future.
    pub fn update_timeout(&mut self, key: &K, timeout: Duration) -> bool {
        if let Some(entry) = self.entries.get(key) {
            self.expirations.reset(&entry.key, timeout);
            true
        } else {
            false
        }
    }

    /// Removes a key from the map returning the value associated with the key that was in the map.
    ///
    /// Return None if the key was not in the map.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(entry) = self.entries.remove(key) {
            self.expirations.remove(&entry.key);
            return Some(entry.value);
        }
        return None;
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all pairs `(k, v)` such that `f(&k,&mut v)` returns false.
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, mut f: F) {
        let expiration = &mut self.expirations;
        self.entries.retain(|key, entry| {
            let result = f(key, &mut entry.value);
            if !result {
                expiration.remove(&entry.key);
            }
            result
        })
    }

    /// Removes all entries from the map.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }
}

impl<K, V> Stream for HashMapDelay<K, V>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone,
{
    type Item = (K, V);
    type Error = &'static str;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.expirations.poll() {
            Ok(Async::Ready(Some(key))) => {
                let key = key.into_inner();
                match self.entries.remove(&key) {
                    Some(entry) => Ok(Async::Ready(Some((key, entry.value)))),
                    None => Err("Value no longer exists in expirations"),
                }
            }
            Ok(Async::Ready(None)) => Ok(Async::Ready(None)),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err("Error polling HashMapDelay"),
        }
    }
}

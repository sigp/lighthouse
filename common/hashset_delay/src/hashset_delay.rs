//NOTE: This is just a specific case of a HashMapDelay.
// The code has been copied to make unique `insert` and `insert_at` functions.

/// The default delay for entries, in seconds. This is only used when `insert()` is used to add
/// entries.
const DEFAULT_DELAY: u64 = 30;

use futures::prelude::*;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio_util::time::delay_queue::{self, DelayQueue};

pub struct HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// The given entries.
    entries: HashMap<K, MapEntry>,
    /// A queue holding the timeouts of each entry.
    expirations: DelayQueue<K>,
    /// The default expiration timeout of an entry.
    default_entry_timeout: Duration,
}

/// A wrapping around entries that adds the link to the entry's expiration, via a `delay_queue` key.
struct MapEntry {
    /// The expiration key for the entry.
    key: delay_queue::Key,
    /// The actual entry.
    value: Instant,
}

impl<K> Default for HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    fn default() -> Self {
        HashSetDelay::new(Duration::from_secs(DEFAULT_DELAY))
    }
}

impl<K> HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// Creates a new instance of `HashSetDelay`.
    pub fn new(default_entry_timeout: Duration) -> Self {
        HashSetDelay {
            entries: HashMap::new(),
            expirations: DelayQueue::new(),
            default_entry_timeout,
        }
    }

    /// Insert an entry into the mapping. Entries will expire after the `default_entry_timeout`.
    pub fn insert(&mut self, key: K) {
        self.insert_at(key, self.default_entry_timeout);
    }

    /// Inserts an entry that will expire at a given instant. If the entry already exists, the
    /// timeout is updated.
    pub fn insert_at(&mut self, key: K, entry_duration: Duration) {
        if self.contains(&key) {
            // update the timeout
            self.update_timeout(&key, entry_duration);
        } else {
            let delay_key = self.expirations.insert(key.clone(), entry_duration);
            let entry = MapEntry {
                key: delay_key,
                value: Instant::now() + entry_duration,
            };
            self.entries.insert(key, entry);
        }
    }

    /// Gets a reference to an entry if it exists.
    ///
    /// Returns None if the entry does not exist.
    pub fn get(&self, key: &K) -> Option<&Instant> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    /// Returns true if the key exists, false otherwise.
    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the length of the mapping.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    /// Return false if the key was not in the map.
    pub fn remove(&mut self, key: &K) -> bool {
        if let Some(entry) = self.entries.remove(key) {
            self.expirations.remove(&entry.key);
            return true;
        }
        false
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all pairs `(k, v)` such that `f(&k,&mut v)` returns false.
    pub fn retain<F: FnMut(&K) -> bool>(&mut self, mut f: F) {
        let expiration = &mut self.expirations;
        self.entries.retain(|key, entry| {
            let result = f(key);
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

    /// Returns a vector of referencing all keys in the map.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.keys()
    }
}

impl<K> Stream for HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    type Item = Result<K, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.expirations.poll_expired(cx) {
            Poll::Ready(Some(Ok(key))) => match self.entries.remove(key.get_ref()) {
                Some(_) => Poll::Ready(Some(Ok(key.into_inner()))),
                None => Poll::Ready(Some(Err("Value no longer exists in expirations".into()))),
            },
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(format!("delay queue error: {:?}", e))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[tokio::test]
    async fn should_not_panic() {
        let key = 2u8;

        let mut map = HashSetDelay::default();

        map.insert(key);
        map.update_timeout(&key, Duration::from_secs(100));

        let fut = |cx: &mut Context| {
            let _ = map.poll_next_unpin(cx);
            let _ = map.poll_next_unpin(cx);
            Poll::Ready(())
        };

        future::poll_fn(fut).await;

        map.insert(key);
        map.update_timeout(&key, Duration::from_secs(100));
    }
}

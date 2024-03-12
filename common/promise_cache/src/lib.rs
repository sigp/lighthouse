use derivative::Derivative;
use itertools::Itertools;
use oneshot_broadcast::{oneshot, Receiver, Sender};
use slog::Logger;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

#[derive(Debug)]
pub struct PromiseCache<K, V, P>
where
    K: Hash + Eq + Clone,
    P: Protect<K>,
{
    cache: HashMap<K, CacheItem<V>>,
    capacity: usize,
    protector: P,
    max_concurrent_promises: usize,
    logger: Logger,
}

/// A value implementing `Protect` is capable of preventing keys of type `K` from being evicted.
///
/// It also dictates an ordering on keys which is used to prioritise evictions.
pub trait Protect<K> {
    type SortKey: Ord;

    fn sort_key(&self, k: &K) -> Self::SortKey;

    fn protect_from_eviction(&self, k: &K) -> bool;

    fn notify_eviction(&self, _k: &K, _log: &Logger) {}
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub enum CacheItem<T> {
    Complete(Arc<T>),
    Promise(Receiver<Arc<T>>),
}

impl<T: std::fmt::Debug> std::fmt::Debug for CacheItem<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            CacheItem::Complete(value) => value.fmt(f),
            CacheItem::Promise(_) => "Promise(..)".fmt(f),
        }
    }
}

#[derive(Debug)]
pub enum PromiseCacheError {
    Failed(oneshot_broadcast::Error),
    MaxConcurrentPromises(usize),
}

pub trait ToArc<T> {
    fn to_arc(&self) -> Arc<T>;
}

impl<T> CacheItem<T> {
    pub fn is_promise(&self) -> bool {
        matches!(self, CacheItem::Promise(_))
    }

    pub fn wait(self) -> Result<Arc<T>, PromiseCacheError> {
        match self {
            CacheItem::Complete(value) => Ok(value),
            CacheItem::Promise(receiver) => receiver.recv().map_err(PromiseCacheError::Failed),
        }
    }
}

impl<T> ToArc<T> for Arc<T> {
    fn to_arc(&self) -> Arc<T> {
        self.clone()
    }
}

impl<T> ToArc<T> for T
where
    T: Clone,
{
    fn to_arc(&self) -> Arc<T> {
        Arc::new(self.clone())
    }
}

impl<K, V, P> PromiseCache<K, V, P>
where
    K: Hash + Eq + Clone,
    P: Protect<K>,
{
    pub fn new(capacity: usize, protector: P, logger: Logger) -> Self {
        // Making the concurrent promises directly configurable is considered overkill for now,
        // so we just derive a vaguely sensible value from the cache size.
        let max_concurrent_promises = std::cmp::max(2, capacity / 8);
        Self {
            cache: HashMap::new(),
            capacity,
            protector,
            max_concurrent_promises,
            logger,
        }
    }

    pub fn get(&mut self, key: &K) -> Option<CacheItem<V>> {
        match self.cache.get(key) {
            // The cache contained the value, return it.
            item @ Some(CacheItem::Complete(_)) => item.cloned(),
            // The cache contains a promise for the value. Check to see if the promise has already
            // been resolved, without waiting for it.
            item @ Some(CacheItem::Promise(receiver)) => match receiver.try_recv() {
                // The promise has already been resolved. Replace the entry in the cache with a
                // `Complete` entry and then return the value.
                Ok(Some(value)) => {
                    let ready = CacheItem::Complete(value);
                    self.insert_cache_item(key.clone(), ready.clone());
                    Some(ready)
                }
                // The promise has not yet been resolved. Return the promise so the caller can await
                // it.
                Ok(None) => item.cloned(),
                // The sender has been dropped without sending a value. There was most likely an
                // error computing the value. Drop the key from the cache and return
                // `None` so the caller can recompute the value.
                //
                // It's worth noting that this is the only place where we removed unresolved
                // promises from the cache. This means unresolved promises will only be removed if
                // we try to access them again. This is OK, since the promises don't consume much
                // memory. We expect that *all* promises should be resolved, unless there is a
                // programming or database error.
                Err(oneshot_broadcast::Error::SenderDropped) => {
                    self.cache.remove(key);
                    None
                }
            },
            // The cache does not have this value and it's not already promised to be computed.
            None => None,
        }
    }

    pub fn contains(&self, key: &K) -> bool {
        self.cache.contains_key(key)
    }

    pub fn insert_value<C: ToArc<V>>(&mut self, key: K, value: &C) {
        if self
            .cache
            .get(&key)
            // Replace the value if it's not present or if it's a promise. A bird in the hand is
            // worth two in the promise-bush!
            .map_or(true, CacheItem::is_promise)
        {
            self.insert_cache_item(key, CacheItem::Complete(value.to_arc()));
        }
    }

    /// Take care of resolving a promise by ensuring the value is made available:
    ///
    /// 1. To all waiting thread that are holding a `Receiver`.
    /// 2. In the cache itself for future callers.
    pub fn resolve_promise<C: ToArc<V>>(&mut self, sender: Sender<Arc<V>>, key: K, value: &C) {
        // Use the sender to notify all actively waiting receivers.
        let arc_value = value.to_arc();
        sender.send(arc_value.clone());

        // Re-insert the value into the cache. The promise may have been evicted in the meantime,
        // but we probably want to keep this value (which resolved recently) over other older cache
        // entries.
        self.insert_value(key, &arc_value);
    }

    /// Prunes the cache first before inserting a new item.
    fn insert_cache_item(&mut self, key: K, cache_item: CacheItem<V>) {
        self.prune_cache();
        self.cache.insert(key, cache_item);
    }

    pub fn create_promise(&mut self, key: K) -> Result<Sender<Arc<V>>, PromiseCacheError> {
        let num_active_promises = self.cache.values().filter(|item| item.is_promise()).count();
        if num_active_promises >= self.max_concurrent_promises {
            return Err(PromiseCacheError::MaxConcurrentPromises(
                num_active_promises,
            ));
        }

        let (sender, receiver) = oneshot();
        self.insert_cache_item(key, CacheItem::Promise(receiver));
        Ok(sender)
    }

    fn prune_cache(&mut self) {
        let target_cache_size = self.capacity.saturating_sub(1);
        if let Some(prune_count) = self.cache.len().checked_sub(target_cache_size) {
            let keys_to_prune = self
                .cache
                .keys()
                .filter(|k| !self.protector.protect_from_eviction(*k))
                .sorted_by_key(|k| self.protector.sort_key(k))
                .take(prune_count)
                .cloned()
                .collect::<Vec<_>>();

            for key in &keys_to_prune {
                self.protector.notify_eviction(key, &self.logger);
                self.cache.remove(key);
            }
        }
    }

    pub fn update_protector(&mut self, protector: P) {
        self.protector = protector;
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn max_concurrent_promises(&self) -> usize {
        self.max_concurrent_promises
    }
}

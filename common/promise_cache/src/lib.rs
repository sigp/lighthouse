//! A cache to avoid redundant computation
//!
//! Cached values (such as states) have to reprocessed (e.g. loaded from disk) if they are not
//! present in their cache. After that, they are added to their cache so that this computation is
//! not needed if there is further need for that value. However, during the necessary computation
//! other threads may also require that value and start computing it, causing additional CPU load
//! and adding unnecessary latency for that second thread.
//!
//! This crate offers the [`PromiseCache`], which does not cache values, but computations for those
//! values (identified by some key), allowing additional threads to simply wait for already ongoing
//! computations instead of needlessly also running that computation. Refer to [`PromiseCache`] for
//! usage instructions.
use oneshot_broadcast::{oneshot, Receiver};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;

/// Caches computation of a value `V` identified by a key `K`.
#[derive(Debug)]
pub struct PromiseCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    cache: Mutex<HashMap<K, Receiver<Result<V, ()>>>>,
}

/// Returned by [`PromiseCache::get_or_compute`] when a computation fails.
pub enum PromiseCacheError<E> {
    /// The computation failed because the passed closure returned an error. For the first thread,
    /// the `Option` will contain the error. As errors are often not clonable, all other threads
    /// will only receive `None` to avoid `E` having to be `Clone`.
    Error(Option<E>),
    /// The computation failed because the passed closure panicked.
    Panic,
}

impl<K, V> PromiseCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Compute a value for the specified key or wait for an already ongoing computation.
    ///
    /// If the closure is successful, the computed value is returned. Otherwise, a
    /// [`PromiseCacheError`] is returned.
    ///
    /// The result values are not retained: as soon as the first thread has returned, new threads
    /// will recompute the value again. Therefore, you should store the resulting value in another
    /// cache, so that threads that are just a bit too late can still use the value computed herein.
    ///
    /// It is possible (and in some cases, advisable) to provide different closures at different
    /// code locations for the same `PromiseCache`: If computation is easier in some contexts,
    /// other threads also may also benefit from that. However, if a thread calls `get_or_compute`
    /// with a "fast" closure while computation is already in progress with a "slow" closure, that
    /// thread may wait longer than it would have by simply using its "fast" closure. This is
    /// unavoidable as we can not compute the complexity of closures.
    ///
    /// NOTE: do not hold any locks while calling this function! Lock necessary locks within the
    /// passed closure instead.
    pub fn get_or_compute<F, E>(&self, key: &K, computation: F) -> Result<V, PromiseCacheError<E>>
    where
        F: FnOnce() -> Result<V, E>,
    {
        let mut cache = self.cache.lock();
        match cache.get(key) {
            Some(item) => {
                let item = item.clone();
                drop(cache);
                item.recv()
                    .map_err(|_| PromiseCacheError::Panic)
                    .and_then(|res| res.map_err(|_| PromiseCacheError::Error(None)))
            }
            None => {
                let (sender, receiver) = oneshot();
                cache.insert(key.clone(), receiver);
                drop(cache);
                let result = computation();
                sender.send(result.as_ref().cloned().map_err(|_| ()));
                self.cache.lock().remove(key);
                result.map_err(|e| PromiseCacheError::Error(Some(e)))
            }
        }
    }
}

impl<K, V> Default for PromiseCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

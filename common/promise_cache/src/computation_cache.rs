use oneshot_broadcast::{oneshot, Receiver};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug)]
pub struct ComputationCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    cache: Mutex<HashMap<K, Receiver<Result<V, ()>>>>,
}

pub enum ComputationCacheError<E> {
    Error(Option<E>),
    Panic,
}

impl<K, V> ComputationCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[allow(clippy::await_holding_lock)] // https://github.com/rust-lang/rust-clippy/issues/6446
    pub fn get_or_compute<F, E>(
        &self,
        key: &K,
        computation: F,
    ) -> Result<V, ComputationCacheError<E>>
    where
        F: FnOnce() -> Result<V, E>,
    {
        let mut cache = self.cache.lock();
        match cache.get(key) {
            Some(item) => {
                let item = item.clone();
                drop(cache);
                item.recv()
                    .map_err(|_| ComputationCacheError::Panic)
                    .and_then(|res| res.map_err(|_| ComputationCacheError::Error(None)))
            }
            None => {
                let (sender, receiver) = oneshot();
                cache.insert(key.clone(), receiver);
                drop(cache);
                match computation() {
                    Ok(value) => {
                        sender.send(Ok(value));
                        Ok(self
                            .cache
                            .lock()
                            .remove(key)
                            .expect("value has vanished")
                            .recv()
                            .expect("we sent the value")
                            .expect("we sent a success"))
                    }
                    Err(err) => {
                        sender.send(Err(()));
                        self.cache.lock().remove(key);
                        Err(ComputationCacheError::Error(Some(err)))
                    }
                }
            }
        }
    }
}

impl<K, V> Default for ComputationCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

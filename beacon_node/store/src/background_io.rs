use crate::{Error, HotColdDB, ItemStore, KeyValueStoreOp, StoreOp};
use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use slog::{debug, error, Logger};
use std::collections::VecDeque;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use types::*;

/// Maximum number of pending operations in the queue
const MAX_QUEUE_SIZE: usize = 1000;

/// Background I/O processor that handles database writes asynchronously
pub struct BackgroundIO<E: EthSpec> {
    /// Channel for sending operations to the background thread
    tx: Sender<Vec<StoreOp<E>>>,
    /// Background thread handle
    thread: Option<JoinHandle<()>>,
    /// In-memory cache for pending writes
    pending_cache: Arc<Mutex<PendingCache<E>>>,
    /// Logger
    log: Logger,
}

/// Cache for storing pending writes that haven't been committed to disk yet
struct PendingCache<E: EthSpec> {
    /// Queue of pending operations
    queue: VecDeque<Vec<StoreOp<E>>>,
    /// Total size of all pending operations
    total_size: usize,
}

impl<E: EthSpec> BackgroundIO<E> {
    pub fn new(db: Arc<HotColdDB<E, impl ItemStore<E>, impl ItemStore<E>>>, log: Logger) -> Self {
        let (tx, rx) = bounded(MAX_QUEUE_SIZE);
        let pending_cache = Arc::new(Mutex::new(PendingCache {
            queue: VecDeque::new(),
            total_size: 0,
        }));
        let pending_cache_clone = Arc::clone(&pending_cache);
        
        let thread = Some(thread::spawn(move || {
            Self::background_thread(db, rx, pending_cache_clone);
        }));

        Self {
            tx,
            thread,
            pending_cache,
            log,
        }
    }

    /// Submit a batch of operations for background processing
    pub fn submit(&self, batch: Vec<StoreOp<E>>) -> Result<(), Error> {
        let mut cache = self.pending_cache.lock();
        
        // If queue is full, process some operations synchronously
        if cache.total_size >= MAX_QUEUE_SIZE {
            debug!(
                self.log,
                "Background IO queue full, processing synchronously";
                "queue_size" => cache.total_size
            );
            return Err(Error::QueueFull);
        }

        // Add to pending cache
        cache.queue.push_back(batch.clone());
        cache.total_size += 1;

        // Send to background thread
        if let Err(e) = self.tx.try_send(batch) {
            error!(
                self.log,
                "Failed to send to background thread";
                "error" => ?e
            );
            return Err(Error::BackgroundThreadError);
        }

        Ok(())
    }

    /// Get a value from the pending cache if it exists
    pub fn get_pending(&self, key: &Hash256) -> Option<StoreOp<E>> {
        let cache = self.pending_cache.lock();
        for batch in cache.queue.iter().rev() {
            for op in batch.iter().rev() {
                match op {
                    StoreOp::PutBlock(k, v) if k == key => {
                        return Some(StoreOp::PutBlock(*k, v.clone()));
                    }
                    StoreOp::PutState(k, v) if k == key => {
                        return Some(StoreOp::PutState(*k, v.clone())); 
                    }
                    _ => continue,
                }
            }
        }
        None
    }

    fn background_thread(
        db: Arc<HotColdDB<E, impl ItemStore<E>, impl ItemStore<E>>>,
        rx: Receiver<Vec<StoreOp<E>>>,
        pending_cache: Arc<Mutex<PendingCache<E>>>,
    ) {
        while let Ok(batch) = rx.recv() {
            // Process the batch
            if let Err(e) = db.do_atomically_with_block_and_blobs_cache(batch.clone()) {
                error!(
                    db.log,
                    "Background IO error";
                    "error" => ?e
                );
            }

            // Remove from pending cache
            let mut cache = pending_cache.lock();
            if let Some(front) = cache.queue.front() {
                if front == &batch {
                    cache.queue.pop_front();
                    cache.total_size -= 1;
                }
            }
        }
    }
}

impl<E: EthSpec> Drop for BackgroundIO<E> {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            drop(self.tx.clone());
            if let Err(e) = thread.join() {
                error!(
                    self.log,
                    "Background thread join error";
                    "error" => ?e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_store::MemoryStore;
    use crate::config::StoreConfig;
    use types::{MainnetEthSpec, MinimalEthSpec};
    use tempfile::tempdir;
    use std::num::NonZeroUsize;

    #[test]
    fn test_background_io_basic() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let spec = Arc::new(ChainSpec::minimal());
        let config = StoreConfig::default();
        
        let store = HotColdDB::open_ephemeral(config, spec.clone(), log.clone())
            .expect("should create store");
        let store = Arc::new(store);
        
        let background_io = BackgroundIO::new(store.clone(), log);
        
        // Create a test block
        let mut block = SignedBeaconBlock::empty(spec.clone());
        block.message.slot = Slot::new(1);
        let block_root = Hash256::random();
        
        // Submit write operation
        let batch = vec![StoreOp::PutBlock(block_root, Arc::new(block.clone()))];
        background_io.submit(batch).expect("should submit");
        
        // Wait a bit for background processing
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Verify the block was written
        let retrieved = store.get_block_with_pending(&block_root)
            .expect("should get block")
            .expect("block should exist");
        
        assert_eq!(retrieved.message.slot, block.message.slot);
    }

    #[test]
    fn test_background_io_queue_full() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let spec = Arc::new(ChainSpec::minimal());
        let config = StoreConfig::default();
        
        let store = HotColdDB::open_ephemeral(config, spec.clone(), log.clone())
            .expect("should create store");
        let store = Arc::new(store);
        
        let background_io = BackgroundIO::new(store, log);
        
        // Fill the queue
        for _ in 0..MAX_QUEUE_SIZE + 1 {
            let batch = vec![StoreOp::PutBlock(Hash256::random(), 
                Arc::new(SignedBeaconBlock::empty(spec.clone())))];
            
            match background_io.submit(batch) {
                Ok(()) => continue,
                Err(Error::QueueFull) => return, // Test passed
                Err(e) => panic!("unexpected error: {:?}", e),
            }
        }
        
        panic!("should have hit queue full error");
    }

    #[test]
    fn test_background_io_pending_cache() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let spec = Arc::new(ChainSpec::minimal());
        let config = StoreConfig::default();
        
        let store = HotColdDB::open_ephemeral(config, spec.clone(), log.clone())
            .expect("should create store");
        let store = Arc::new(store);
        
        let background_io = BackgroundIO::new(store, log);
        
        // Create a test block
        let mut block = SignedBeaconBlock::empty(spec.clone());
        block.message.slot = Slot::new(1);
        let block_root = Hash256::random();
        
        // Submit write operation
        let batch = vec![StoreOp::PutBlock(block_root, Arc::new(block.clone()))];
        background_io.submit(batch).expect("should submit");
        
        // Check pending cache immediately
        if let Some(StoreOp::PutBlock(k, v)) = background_io.get_pending(&block_root) {
            assert_eq!(k, block_root);
            assert_eq!(v.message.slot, block.message.slot);
        } else {
            panic!("pending operation not found");
        }
    }
} 
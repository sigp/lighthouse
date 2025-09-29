use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use tokio::sync::broadcast;
use types::Hash256;

/// Represents the status of a block during the data availability import process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BlockStatus {
    /// Block is pending processing
    Pending = 0,
    /// Block is currently being executed
    Executing = 1,
    /// Block has been determined to be invalid
    Invalid = 2,
    /// Block is currently being imported
    Importing = 3,
    /// Block has been successfully imported
    Imported = 4,
}

impl BlockStatus {
    /// Converts a u8 value to a Status enum.
    /// Returns None if the value is invalid.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(BlockStatus::Pending),
            1 => Some(BlockStatus::Executing),
            2 => Some(BlockStatus::Invalid),
            3 => Some(BlockStatus::Importing),
            4 => Some(BlockStatus::Imported),
            _ => None,
        }
    }

    /// Converts the Status to its u8 representation.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Returns true if the status represents an active processing state
    pub fn is_active(&self) -> bool {
        matches!(self, BlockStatus::Executing | BlockStatus::Importing)
    }

    /// Returns true if the status represents a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, BlockStatus::Invalid | BlockStatus::Imported)
    }
}

/// A thread-safe status tracking table for Ethereum blocks during data availability import.
///
/// This table uses DashMap for lock-free concurrent access and AtomicU8 values for
/// efficient atomic operations on status transitions to prevent race conditions during
/// block processing.
#[derive(Debug)]
pub struct BlockStatusTable {
    /// The underlying concurrent hash map storing block status as AtomicU8
    table: DashMap<Hash256, AtomicU8>,
    /// Broadcast channels for notifying subscribers of status changes
    notifiers: DashMap<Hash256, broadcast::Sender<BlockStatus>>,
    /// Counter for tracking the number of entries (for metrics/debugging)
    entry_count: AtomicUsize,
}

impl BlockStatusTable {
    /// Channel capacity - sufficient for all possible state transitions
    const CHANNEL_CAPACITY: usize = 16;

    /// Creates a new empty status table.
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
            notifiers: DashMap::new(),
            entry_count: AtomicUsize::new(0),
        }
    }

    /// Subscribe to status updates for a specific block.
    /// Returns None if the block is not being tracked.
    ///
    /// Late subscribers will receive all future status changes but not past ones.
    pub fn subscribe(
        &self,
        block_hash: &Hash256,
    ) -> Option<(BlockStatus, broadcast::Receiver<BlockStatus>)> {
        // by subscribing before reading the current status, a race condition is possible where
        // the subscribing thread receives a status and then when they await the channel, they receive
        // the same status again. This is preferable to the reverse race condition where an old status is
        // read and the subscriber doesn't send the update to the latest status.
        let rx = self.notifiers.get(block_hash)?.subscribe();
        let current_status = self.get_status(block_hash)?;
        Some((current_status, rx))
    }

    /// Gets the current status of a block.
    ///
    /// Returns `None` if the block is not tracked in the table.
    pub fn get_status(&self, block_hash: &Hash256) -> Option<BlockStatus> {
        self.table.get(block_hash).and_then(|entry| {
            let value = entry.value().load(Ordering::Acquire);
            BlockStatus::from_u8(value)
        })
    }

    /// Atomically compares and swaps the status of a block.
    ///
    /// This operation is atomic and will only succeed if the current status
    /// matches the expected status. Returns `true` if the swap succeeded,
    /// `false` otherwise.
    ///
    /// # Arguments
    /// * `block_hash` - The hash of the block to update
    /// * `expected` - The expected current status
    /// * `new` - The new status to set
    pub fn compare_and_swap_status(
        &self,
        block_hash: &Hash256,
        expected: BlockStatus,
        new: BlockStatus,
    ) -> bool {
        let success = match self.table.get(block_hash) {
            Some(entry) => {
                let atomic_value = entry.value();
                atomic_value
                    .compare_exchange_weak(
                        expected.to_u8(),
                        new.to_u8(),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            }
            None => false,
        };

        // Notify subscribers if the transition succeeded
        if success && let Some(tx) = self.notifiers.get(block_hash) {
            // Ignore send errors - means no active receivers
            let _ = tx.send(new);
        }

        success
    }

    /// Inserts a new block with Pending status.
    ///
    /// Returns `true` if the block was inserted (i.e., it wasn't already present),
    /// `false` if the block already exists in the table.
    pub fn insert_pending(&self, block_hash: Hash256) -> bool {
        // Create the broadcast channel
        let (tx, _rx) = broadcast::channel(Self::CHANNEL_CAPACITY);

        match self.table.entry(block_hash) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(AtomicU8::new(BlockStatus::Pending.to_u8()));
                self.notifiers.insert(block_hash, tx);
                self.entry_count.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Removes a block from the status table.
    ///
    /// Returns the previous status if the block was present, `None` otherwise.
    pub fn remove(&self, block_hash: &Hash256) -> Option<BlockStatus> {
        // Remove from both maps
        let status = self
            .table
            .remove(block_hash)
            .and_then(|(_, atomic_status)| {
                let status_value = atomic_status.load(Ordering::Acquire);
                BlockStatus::from_u8(status_value)
            });

        // Clean up the notifier channel
        self.notifiers.remove(block_hash);

        if status.is_some() {
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }

        status
    }

    /// Returns the number of entries currently in the table.
    ///
    /// Note: This is an approximate count that may be slightly inaccurate
    /// due to concurrent operations, but is useful for monitoring and debugging.
    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Returns the number of entries in each status state.
    ///
    /// This method is primarily intended for debugging and monitoring purposes.
    /// The counts are approximate due to the concurrent nature of the table.
    pub fn status_counts(&self) -> BlockStatusCounts {
        let mut counts = BlockStatusCounts::default();

        for entry in self.table.iter() {
            let status_value = entry.value().load(Ordering::Acquire);
            if let Some(status) = BlockStatus::from_u8(status_value) {
                match status {
                    BlockStatus::Pending => counts.pending += 1,
                    BlockStatus::Executing => counts.executing += 1,
                    BlockStatus::Invalid => counts.invalid += 1,
                    BlockStatus::Importing => counts.importing += 1,
                    BlockStatus::Imported => counts.imported += 1,
                }
            }
        }

        counts
    }

    /// Clears all entries from the table.
    ///
    /// This method should be used with caution as it removes all tracking information.
    pub fn clear(&self) {
        self.table.clear();
        self.entry_count.store(0, Ordering::Relaxed);
    }
}

impl Default for BlockStatusTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Counts of entries in each status state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockStatusCounts {
    pub pending: usize,
    pub executing: usize,
    pub invalid: usize,
    pub importing: usize,
    pub imported: usize,
}

impl BlockStatusCounts {
    /// Returns the total number of entries across all statuses.
    pub fn total(&self) -> usize {
        self.pending + self.executing + self.invalid + self.importing + self.imported
    }

    /// Returns the number of entries in terminal states.
    pub fn terminal(&self) -> usize {
        self.invalid + self.imported
    }

    /// Returns the number of entries in active processing states.
    pub fn active(&self) -> usize {
        self.executing + self.importing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// Helper function to create a test block hash
    fn test_hash(n: u64) -> Hash256 {
        // this needs to be padded to 32 bytes
        let mut bytes = [0; 32];
        bytes[0..8].copy_from_slice(&n.to_be_bytes());
        Hash256::from_slice(&bytes)
    }

    #[test]
    fn test_new_status_table() {
        let table = BlockStatusTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_insert_pending() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);

        // First insertion should succeed
        assert!(table.insert_pending(hash));
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
        assert_eq!(table.len(), 1);

        // Second insertion of same hash should fail
        assert!(!table.insert_pending(hash));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_get_status() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);

        // Non-existent hash should return None
        assert_eq!(table.get_status(&hash), None);

        // Insert and verify
        table.insert_pending(hash);
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
    }

    #[test]
    fn test_compare_and_swap_status() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);

        // CAS on non-existent entry should fail
        assert!(!table.compare_and_swap_status(
            &hash,
            BlockStatus::Pending,
            BlockStatus::Executing
        ));

        // Insert entry
        table.insert_pending(hash);

        // Successful CAS
        assert!(table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Executing));
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Executing));

        // Failed CAS with wrong expected value
        assert!(!table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Invalid));
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Executing));

        // Successful CAS to terminal state
        assert!(table.compare_and_swap_status(
            &hash,
            BlockStatus::Executing,
            BlockStatus::Imported
        ));
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Imported));
    }

    #[test]
    fn test_remove() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);

        // Remove non-existent entry
        assert_eq!(table.remove(&hash), None);

        // Insert and remove
        table.insert_pending(hash);
        assert_eq!(table.len(), 1);
        assert_eq!(table.remove(&hash), Some(BlockStatus::Pending));
        assert_eq!(table.len(), 0);
        assert_eq!(table.get_status(&hash), None);
    }

    #[test]
    fn test_status_counts() {
        let table = BlockStatusTable::new();
        let hashes: Vec<Hash256> = (1..=5).map(test_hash).collect();

        // Insert and set different statuses
        for &hash in &hashes {
            table.insert_pending(hash);
        }

        table.compare_and_swap_status(&hashes[0], BlockStatus::Pending, BlockStatus::Executing);
        table.compare_and_swap_status(&hashes[1], BlockStatus::Pending, BlockStatus::Invalid);
        table.compare_and_swap_status(&hashes[2], BlockStatus::Pending, BlockStatus::Importing);
        table.compare_and_swap_status(&hashes[3], BlockStatus::Pending, BlockStatus::Imported);
        // hashes[4] remains Pending

        let counts = table.status_counts();
        assert_eq!(counts.pending, 1);
        assert_eq!(counts.executing, 1);
        assert_eq!(counts.invalid, 1);
        assert_eq!(counts.importing, 1);
        assert_eq!(counts.imported, 1);
        assert_eq!(counts.total(), 5);
        assert_eq!(counts.terminal(), 2);
        assert_eq!(counts.active(), 2);
    }

    #[test]
    fn test_status_methods() {
        assert!(BlockStatus::Invalid.is_terminal());
        assert!(BlockStatus::Imported.is_terminal());
        assert!(!BlockStatus::Pending.is_terminal());
        assert!(!BlockStatus::Executing.is_terminal());
        assert!(!BlockStatus::Importing.is_terminal());

        assert!(BlockStatus::Executing.is_active());
        assert!(BlockStatus::Importing.is_active());
        assert!(!BlockStatus::Pending.is_active());
        assert!(!BlockStatus::Invalid.is_active());
        assert!(!BlockStatus::Imported.is_active());
    }

    #[test]
    fn test_clear() {
        let table = BlockStatusTable::new();
        let hash1 = test_hash(1);
        let hash2 = test_hash(2);

        table.insert_pending(hash1);
        table.insert_pending(hash2);
        assert_eq!(table.len(), 2);

        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.get_status(&hash1), None);
        assert_eq!(table.get_status(&hash2), None);
    }

    #[test]
    fn test_concurrent_access() {
        let table = Arc::new(BlockStatusTable::new());
        let num_threads = 10;
        let operations_per_thread = 100;

        let mut handles = Vec::new();

        // Spawn threads that perform concurrent operations
        for thread_id in 0..num_threads {
            let table_clone = Arc::clone(&table);
            let handle = thread::spawn(move || {
                for op_id in 0..operations_per_thread {
                    let hash = test_hash((thread_id * operations_per_thread + op_id) as u64);

                    // Insert
                    table_clone.insert_pending(hash);

                    // Try to transition through states
                    table_clone.compare_and_swap_status(
                        &hash,
                        BlockStatus::Pending,
                        BlockStatus::Executing,
                    );

                    // Small delay to increase chance of contention
                    thread::sleep(Duration::from_nanos(1));

                    table_clone.compare_and_swap_status(
                        &hash,
                        BlockStatus::Executing,
                        BlockStatus::Imported,
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        // Verify final state
        assert_eq!(table.len(), num_threads * operations_per_thread);

        // All entries should be in either Executing or Imported state
        let counts = table.status_counts();
        assert_eq!(counts.pending, 0);
        assert_eq!(counts.invalid, 0);
        assert_eq!(counts.importing, 0);
        assert_eq!(
            counts.executing + counts.imported,
            num_threads * operations_per_thread
        );
    }

    #[test]
    fn test_atomic_operations_performance() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);

        // Test that atomic operations work correctly
        table.insert_pending(hash);

        // Test multiple rapid transitions
        for _ in 0..1000 {
            assert!(table.compare_and_swap_status(
                &hash,
                BlockStatus::Pending,
                BlockStatus::Executing
            ));
            assert!(table.compare_and_swap_status(
                &hash,
                BlockStatus::Executing,
                BlockStatus::Pending
            ));
        }

        // Verify final state
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
    }

    #[test]
    fn test_status_conversion() {
        // Test all valid conversions
        assert_eq!(BlockStatus::from_u8(0), Some(BlockStatus::Pending));
        assert_eq!(BlockStatus::from_u8(1), Some(BlockStatus::Executing));
        assert_eq!(BlockStatus::from_u8(2), Some(BlockStatus::Invalid));
        assert_eq!(BlockStatus::from_u8(3), Some(BlockStatus::Importing));
        assert_eq!(BlockStatus::from_u8(4), Some(BlockStatus::Imported));
        assert_eq!(BlockStatus::from_u8(5), None);
        assert_eq!(BlockStatus::from_u8(255), None);

        // Test round-trip conversions
        for &status in &[
            BlockStatus::Pending,
            BlockStatus::Executing,
            BlockStatus::Invalid,
            BlockStatus::Importing,
            BlockStatus::Imported,
        ] {
            assert_eq!(BlockStatus::from_u8(status.to_u8()), Some(status));
        }
    }

    #[test]
    fn test_concurrent_cas_contention() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);
        table.insert_pending(hash);

        let num_threads = 10;
        let operations_per_thread = 100;
        let mut handles = Vec::new();

        // Spawn threads that compete to transition the same block
        for _thread_id in 0..num_threads {
            let table_clone = Arc::clone(&table);
            let handle = thread::spawn(move || {
                let mut successful_cas = 0;
                for _ in 0..operations_per_thread {
                    // Try to transition from Pending to Executing
                    if table_clone.compare_and_swap_status(
                        &hash,
                        BlockStatus::Pending,
                        BlockStatus::Executing,
                    ) {
                        successful_cas += 1;
                        // Immediately transition back to allow other threads to compete
                        table_clone.compare_and_swap_status(
                            &hash,
                            BlockStatus::Executing,
                            BlockStatus::Pending,
                        );
                    }
                }
                successful_cas
            });
            handles.push(handle);
        }

        // Collect results
        let mut total_successful = 0;
        for handle in handles {
            total_successful += handle.join().expect("Thread should complete");
        }

        // Each thread should have had some successful CAS operations
        // The exact number depends on scheduling, but should be reasonable
        assert!(total_successful > 0);
        assert!(total_successful <= num_threads * operations_per_thread);

        // Final state should be consistent
        let final_status = table.get_status(&hash);
        assert!(
            final_status == Some(BlockStatus::Pending)
                || final_status == Some(BlockStatus::Executing)
        );
    }

    #[tokio::test]
    async fn test_subscribe_notifications() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);

        // Insert pending block
        table.insert_pending(hash);

        // Subscribe to updates
        let (current_status, mut rx) = table.subscribe(&hash).expect("Should be able to subscribe");
        assert_eq!(current_status, BlockStatus::Pending);

        // Transition to Executing
        assert!(table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Executing));

        // Should receive notification
        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Executing);

        // Transition to Importing
        assert!(table.compare_and_swap_status(
            &hash,
            BlockStatus::Executing,
            BlockStatus::Importing
        ));

        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Importing);

        // Transition to Imported (terminal state)
        assert!(table.compare_and_swap_status(
            &hash,
            BlockStatus::Importing,
            BlockStatus::Imported
        ));

        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Imported);
    }

    #[tokio::test]
    async fn test_subscribe_race_condition() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);

        table.insert_pending(hash);

        // Spawn a task that will transition the status immediately
        let table_clone = Arc::clone(&table);
        let transition_handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            table_clone.compare_and_swap_status(
                &hash,
                BlockStatus::Pending,
                BlockStatus::Executing,
            );
        });

        // Subscribe (might race with the transition above)
        let (current_status, mut rx) = table.subscribe(&hash).expect("Should be able to subscribe");

        transition_handle
            .await
            .expect("Transition task should complete");

        // Depending on race outcome:
        // - If we subscribed before transition: current_status = Pending, rx will receive Executing
        // - If we subscribed after transition: current_status = Executing, rx might immediately have Executing

        if current_status == BlockStatus::Pending {
            // Should receive the Executing notification
            let status = tokio::time::timeout(tokio::time::Duration::from_secs(1), rx.recv())
                .await
                .expect("Should not timeout")
                .expect("Should receive notification");
            assert_eq!(status, BlockStatus::Executing);
        } else {
            // Already at Executing, might receive duplicate or might not
            assert_eq!(current_status, BlockStatus::Executing);
        }

        // Verify final state
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Executing));
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);

        table.insert_pending(hash);

        // Create multiple subscribers
        let (status1, mut rx1) = table.subscribe(&hash).expect("Should subscribe");
        let (status2, mut rx2) = table.subscribe(&hash).expect("Should subscribe");
        let (status3, mut rx3) = table.subscribe(&hash).expect("Should subscribe");

        assert_eq!(status1, BlockStatus::Pending);
        assert_eq!(status2, BlockStatus::Pending);
        assert_eq!(status3, BlockStatus::Pending);

        // Transition state
        assert!(table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Executing));

        // All subscribers should receive the notification
        let s1 = rx1.recv().await.expect("rx1 should receive");
        let s2 = rx2.recv().await.expect("rx2 should receive");
        let s3 = rx3.recv().await.expect("rx3 should receive");

        assert_eq!(s1, BlockStatus::Executing);
        assert_eq!(s2, BlockStatus::Executing);
        assert_eq!(s3, BlockStatus::Executing);
    }

    #[tokio::test]
    async fn test_subscribe_to_nonexistent_block() {
        let table = BlockStatusTable::new();
        let hash = test_hash(999);

        // Should return None for non-existent block
        assert!(table.subscribe(&hash).is_none());
    }

    #[tokio::test]
    async fn test_subscribe_after_removal() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);

        table.insert_pending(hash);
        let (_status, mut rx) = table.subscribe(&hash).expect("Should subscribe");

        // Transition to terminal state and remove
        assert!(table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Imported));

        // Receive the notification
        let status = rx.recv().await.expect("Should receive Imported");
        assert_eq!(status, BlockStatus::Imported);

        // Remove from table
        table.remove(&hash);

        // Channel should close (no more senders)
        match rx.recv().await {
            Err(broadcast::error::RecvError::Closed) => {
                // Expected - channel closed after removal
            }
            other => panic!("Expected channel to be closed, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_subscribe_with_late_subscriber() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);

        table.insert_pending(hash);

        // First subscriber
        let (_status1, mut rx1) = table.subscribe(&hash).expect("Should subscribe");

        // Transition through multiple states
        assert!(table.compare_and_swap_status(&hash, BlockStatus::Pending, BlockStatus::Executing));
        assert!(table.compare_and_swap_status(
            &hash,
            BlockStatus::Executing,
            BlockStatus::Importing
        ));

        // Late subscriber should get current state
        let (status2, mut rx2) = table.subscribe(&hash).expect("Should subscribe");
        assert_eq!(status2, BlockStatus::Importing);

        // First subscriber should have received both notifications
        assert_eq!(
            rx1.recv().await.expect("Should receive"),
            BlockStatus::Executing
        );
        assert_eq!(
            rx1.recv().await.expect("Should receive"),
            BlockStatus::Importing
        );

        // Now both should receive future transitions
        assert!(table.compare_and_swap_status(
            &hash,
            BlockStatus::Importing,
            BlockStatus::Imported
        ));

        assert_eq!(
            rx1.recv().await.expect("Should receive"),
            BlockStatus::Imported
        );
        assert_eq!(
            rx2.recv().await.expect("Should receive"),
            BlockStatus::Imported
        );
    }
}

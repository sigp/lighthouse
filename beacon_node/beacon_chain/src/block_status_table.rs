use crate::block_verification::BlockError;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::sync::broadcast;
use types::{Hash256, Slot};

#[derive(Debug)]
pub enum Error {
    BlockNotFound,
    InvalidStatusTransition {
        expected: BlockStatus,
        found: BlockStatus,
    },
    InvalidStatus(u8),
    BlockAlreadyInvalid(BlockError),
}

/// Represents the status of a block during the data availability import process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BlockStatus {
    /// Block (or blob) has been seen
    Seen = 0,
    /// Someone is running process_block() on the block
    Processing = 1,
    /// process_block() finished, now waiting for blobs to be available
    Pending = 2,
    /// Block is currently being executed
    Executing = 3,
    /// Block is currently being imported
    Importing = 4,
    /// Block has been successfully imported
    Imported = 5,
    /// Block status was invalid (this should never happen)
    /// This keeps us from needing to return Results everywhere
    Unknown = 255,
}

impl BlockStatus {
    /// Channel capacity - sufficient for all possible state transitions
    pub const CHANNEL_CAPACITY: usize = 16;

    /// Converts a u8 value to a Status enum.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => BlockStatus::Seen,
            1 => BlockStatus::Processing,
            2 => BlockStatus::Pending,
            3 => BlockStatus::Executing,
            4 => BlockStatus::Importing,
            5 => BlockStatus::Imported,
            _ => BlockStatus::Unknown,
        }
    }

    /// Converts the Status to its u8 representation.
    pub fn to_u8(self) -> u8 {
        match self {
            BlockStatus::Seen => 0,
            BlockStatus::Processing => 1,
            BlockStatus::Pending => 2,
            BlockStatus::Executing => 3,
            BlockStatus::Importing => 4,
            BlockStatus::Imported => 5,
            BlockStatus::Unknown => 255,
        }
    }

    pub fn is_seen(&self) -> bool {
        self == &BlockStatus::Seen
    }

    pub fn is_processing(&self) -> bool {
        self == &BlockStatus::Processing
    }

    pub fn is_pending(&self) -> bool {
        self == &BlockStatus::Pending
    }

    pub fn is_past_pending(&self) -> bool {
        self > &BlockStatus::Pending
    }

    pub fn is_imported(&self) -> bool {
        self == &BlockStatus::Imported
    }
}

struct ValidEntry {
    status: AtomicU8,
    slot: Slot,
    sender: broadcast::Sender<BlockState>,
}

struct InvalidEntry {
    slot: Slot,
    block_error: BlockError,
}

enum BlockStatusEntry {
    Valid(ValidEntry),
    Invalid(InvalidEntry),
}

#[derive(Clone, Debug)]
pub enum BlockState {
    Valid(BlockStatus),
    Invalid(BlockError),
}

impl BlockStatusEntry {
    pub fn new(status: BlockStatus, slot: Slot) -> Self {
        let (sender, _rx) = broadcast::channel(BlockStatus::CHANNEL_CAPACITY);
        Self::Valid(ValidEntry {
            status: AtomicU8::new(status.to_u8()),
            slot,
            sender,
        })
    }

    pub fn new_invalid(slot: Slot, block_error: BlockError) -> Self {
        Self::Invalid(InvalidEntry { slot, block_error })
    }

    pub fn new_subscribe(
        status: BlockStatus,
        slot: Slot,
    ) -> (Self, broadcast::Receiver<BlockState>) {
        let (sender, rx) = broadcast::channel(BlockStatus::CHANNEL_CAPACITY);
        (
            Self::Valid(ValidEntry {
                status: AtomicU8::new(status.to_u8()),
                slot,
                sender,
            }),
            rx,
        )
    }

    pub fn state(&self) -> BlockState {
        match self {
            Self::Valid(entry) => {
                BlockState::Valid(BlockStatus::from_u8(entry.status.load(Ordering::Acquire)))
            }
            Self::Invalid(entry) => BlockState::Invalid(entry.block_error.clone()),
        }
    }

    pub fn slot(&self) -> Slot {
        match self {
            Self::Valid(entry) => entry.slot,
            Self::Invalid(entry) => entry.slot,
        }
    }

    // transition to a valid status
    pub fn transition(&self, expected: BlockStatus, new: BlockStatus) -> Result<(), Error> {
        match self {
            Self::Valid(entry) => {
                match entry
                    .status
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        if value == expected.to_u8() {
                            Some(new.to_u8())
                        } else {
                            None
                        }
                    }) {
                    Ok(_) => {
                        // Notify subscribers of the new status
                        // Ignore send errors - means no active receivers
                        let _ = entry.sender.send(BlockState::Valid(new));
                        Ok(())
                    }
                    Err(actual_value) => Err(Error::InvalidStatusTransition {
                        expected,
                        found: BlockStatus::from_u8(actual_value),
                    }),
                }
            }
            Self::Invalid(entry) => Err(Error::BlockAlreadyInvalid(entry.block_error.clone())),
        }
    }

    pub fn subscribe(&self) -> (BlockState, broadcast::Receiver<BlockState>) {
        match self {
            Self::Valid(v) => {
                // by subscribing before reading the current status, a race condition is possible where
                // the subscribing thread receives a status and then when they await the channel, they receive
                // the same status again. This is preferable to the reverse race condition where an old status is
                // read and the subscriber doesn't send the update to the latest status.
                let rx = v.sender.subscribe();
                let cur = BlockState::Valid(BlockStatus::from_u8(v.status.load(Ordering::Acquire)));
                (cur, rx)
            }
            Self::Invalid(inv) => {
                // Provide a terminal, already-invalid stream: send once, then close.
                let (tx, rx) = broadcast::channel(1);
                let _ = tx.send(BlockState::Invalid(inv.block_error.clone()));
                drop(tx);
                (BlockState::Invalid(inv.block_error.clone()), rx)
            }
        }
    }
}

/// A thread-safe status tracking table for Ethereum blocks during data availability import.
///
/// This table uses DashMap for lock-free concurrent access and AtomicU8 values for
/// efficient atomic operations on status transitions to prevent race conditions during
/// block processing.
pub struct BlockStatusTable {
    /// The underlying concurrent hash map storing block status as AtomicU8
    table: DashMap<Hash256, Arc<BlockStatusEntry>>,
}

impl BlockStatusTable {
    /// Creates a new empty status table.
    pub fn new() -> Self {
        Self {
            table: DashMap::new(),
        }
    }

    /// Inserts a new block with Pending status.
    ///
    /// Returns `true` if the block was inserted (i.e., it wasn't already present),
    /// `false` if the block already exists in the table.
    pub fn insert(
        &self,
        block_hash: Hash256,
        slot: Slot,
        status: BlockStatus,
    ) -> (bool, BlockState) {
        match self.table.entry(block_hash) {
            Entry::Occupied(o) => (false, o.get().state()),
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(BlockStatusEntry::new(status, slot)));
                (true, BlockState::Valid(status))
            }
        }
    }

    pub fn insert_subscribe(
        &self,
        block_hash: Hash256,
        slot: Slot,
        status: BlockStatus,
    ) -> (bool, BlockState, broadcast::Receiver<BlockState>) {
        match self.table.entry(block_hash) {
            Entry::Occupied(o) => {
                let (state, rx) = o.get().subscribe();
                (false, state, rx)
            }
            Entry::Vacant(entry) => {
                let (status_entry, rx) = BlockStatusEntry::new_subscribe(status, slot);
                entry.insert(Arc::new(status_entry));
                (true, BlockState::Valid(status), rx)
            }
        }
    }

    /// Atomically compares and swaps the status of a block.
    ///
    /// This operation is atomic and will only succeed if the current status
    /// matches the expected status. Returns `Ok(())` if the swap succeeded,
    /// `Err` otherwise.
    ///
    /// # Arguments
    /// * `block_hash` - The hash of the block to update
    /// * `expected` - The expected current status
    /// * `new` - The new status to set
    pub fn transition(
        &self,
        block_hash: &Hash256,
        expected: BlockStatus,
        new: BlockStatus,
    ) -> Result<(), Error> {
        let entry = self
            .table
            .get(block_hash)
            // clone the arc and drop the dashmap guard quickly
            .map(|guard| guard.clone())
            .ok_or(Error::BlockNotFound)?;

        entry.transition(expected, new)
    }

    /// Marks a block as invalid.
    ///
    /// This method will transition the block to Invalid and store the error.
    pub fn mark_invalid(&self, block_hash: Hash256, block_error: BlockError) -> Result<(), Error> {
        match self.table.entry(block_hash) {
            Entry::Occupied(mut o) => {
                match o.get().as_ref() {
                    BlockStatusEntry::Valid(entry) => {
                        let tx = entry.sender.clone();
                        // send the invalid state to the subscribers
                        let _ = tx.send(BlockState::Invalid(block_error.clone()));
                        // swap the valid entry for an invalid entry
                        o.insert(Arc::new(BlockStatusEntry::new_invalid(
                            entry.slot,
                            block_error,
                        )));
                        Ok(())
                    }
                    BlockStatusEntry::Invalid(entry) => {
                        Err(Error::BlockAlreadyInvalid(entry.block_error.clone()))
                    }
                }
            }
            Entry::Vacant(_) => Err(Error::BlockNotFound),
        }
    }

    /// Subscribe to status updates for a specific block.
    /// Returns None if the block is not being tracked.
    ///
    /// Late subscribers will receive all future status changes but not past ones.
    pub fn subscribe(
        &self,
        block_hash: &Hash256,
    ) -> Option<(BlockState, broadcast::Receiver<BlockState>)> {
        let entry = self
            .table
            .get(block_hash)
            // clone the arc and drop the dashmap guard quickly
            .map(|guard| guard.clone())?;

        Some(entry.subscribe())
    }

    /// Gets the current status of a block.
    ///
    /// Returns `None` if the block is not tracked in the table.
    pub fn get_state(&self, block_hash: &Hash256) -> Option<BlockState> {
        let entry = self
            .table
            .get(block_hash)
            // clone the arc and quickly drop dashmap guard
            .map(|guard| guard.clone())?;

        Some(entry.state())
    }

    /// Removes a block from the status table.
    ///
    /// Returns the previous status if the block was present, `None` otherwise.
    pub fn remove(&self, block_hash: &Hash256) -> Option<BlockState> {
        // Remove entry from table
        self.table
            .remove(block_hash)
            .map(|(_, entry)| entry.state())
    }

    /// Prunes entries with a slot lower than the given slot.
    pub fn prune_finalized(&self, finalized_slot: Slot) {
        self.table.retain(|_, entry| entry.slot() >= finalized_slot);
    }

    /// Returns the number of entries currently in the table.
    ///
    /// Note: This is an approximate count that may be slightly inaccurate
    /// due to concurrent operations, but is useful for monitoring and debugging.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Clears all entries from the table.
    ///
    /// This method should be used with caution as it removes all tracking information.
    pub fn clear(&self) {
        self.table.clear();
    }
}

impl Default for BlockStatusTable {
    fn default() -> Self {
        Self::new()
    }
}

/*
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
    fn test_insert() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);
        let slot = Slot::new(1);

        // First insertion should succeed
        let (inserted, status) = table.insert(hash, slot, BlockStatus::Pending);
        assert!(inserted);
        assert_eq!(status, BlockStatus::Pending);
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
        assert_eq!(table.len(), 1);

        // Second insertion of same hash should fail
        let (inserted, status) = table.insert(hash, slot, BlockStatus::Pending);
        assert!(!inserted);
        assert_eq!(status, BlockStatus::Pending);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_get_status() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);
        let slot = Slot::new(1);

        // Non-existent hash should return None
        assert_eq!(table.get_status(&hash), None);

        // Insert and verify
        table.insert(hash, slot, BlockStatus::Pending);
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
    }

    #[test]
    fn test_transition() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);
        let slot = Slot::new(1);

        // CAS on non-existent entry should fail
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                .is_err()
        );

        // Insert entry
        table.insert(hash, slot, BlockStatus::Pending);

        // Successful CAS
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                .is_ok()
        );
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Executing));

        // Failed CAS with wrong expected value
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Invalid)
                .is_err()
        );
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Executing));

        // Successful CAS to terminal state
        assert!(
            table
                .transition(&hash, BlockStatus::Executing, BlockStatus::Imported)
                .is_ok()
        );
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Imported));
    }

    #[test]
    fn test_remove() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);
        let slot = Slot::new(1);

        // Remove non-existent entry
        assert_eq!(table.remove(&hash), None);

        // Insert and remove
        table.insert(hash, slot, BlockStatus::Pending);
        assert_eq!(table.len(), 1);
        assert_eq!(table.remove(&hash), Some(BlockStatus::Pending));
        assert_eq!(table.len(), 0);
        assert_eq!(table.get_status(&hash), None);
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
        let slot1 = Slot::new(1);
        let slot2 = Slot::new(2);

        table.insert(hash1, slot1, BlockStatus::Pending);
        table.insert(hash2, slot2, BlockStatus::Pending);
        assert_eq!(table.len(), 2);

        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.get_status(&hash1), None);
        assert_eq!(table.get_status(&hash2), None);
    }

    #[test]
    fn test_prune_finalized() {
        let table = BlockStatusTable::new();
        let blocks = 32usize;
        for i in 0..blocks {
            let hash = test_hash(i as u64);
            let slot = Slot::new(i as u64);
            table.insert(hash, slot, BlockStatus::Pending);
        }
        table.prune_finalized(Slot::new(16));
        assert_eq!(table.len(), 16);
        for i in 0..blocks {
            let hash = test_hash(i as u64);
            if i < 16 {
                assert_eq!(table.get_status(&hash), None);
            } else {
                assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
            }
        }
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
                    let slot = Slot::new(1);

                    // Insert
                    table_clone.insert(hash, slot, BlockStatus::Pending);

                    // Try to transition through states
                    assert!(
                        table_clone
                            .transition(&hash, BlockStatus::Pending, BlockStatus::Executing,)
                            .is_ok()
                    );

                    // Small delay to increase chance of contention
                    thread::sleep(Duration::from_nanos(1));

                    assert!(
                        table_clone
                            .transition(&hash, BlockStatus::Executing, BlockStatus::Imported,)
                            .is_ok()
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
    }

    #[test]
    fn test_atomic_operations_performance() {
        let table = BlockStatusTable::new();
        let hash = test_hash(1);
        let slot = Slot::new(1);

        // Test that atomic operations work correctly
        table.insert(hash, slot, BlockStatus::Pending);

        // Test multiple rapid transitions
        for _ in 0..1000 {
            assert!(
                table
                    .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                    .is_ok()
            );
            assert!(
                table
                    .transition(&hash, BlockStatus::Executing, BlockStatus::Pending)
                    .is_ok()
            );
        }

        // Verify final state
        assert_eq!(table.get_status(&hash), Some(BlockStatus::Pending));
    }

    #[test]
    fn test_status_conversion() {
        // Test all valid conversions
        assert_eq!(BlockStatus::from_u8(0), Ok(BlockStatus::Seen));
        assert_eq!(BlockStatus::from_u8(1), Ok(BlockStatus::Processing));
        assert_eq!(BlockStatus::from_u8(2), Ok(BlockStatus::Pending));
        assert_eq!(BlockStatus::from_u8(3), Ok(BlockStatus::Executing));
        assert_eq!(BlockStatus::from_u8(4), Ok(BlockStatus::Invalid));
        assert_eq!(BlockStatus::from_u8(5), Ok(BlockStatus::Importing));
        assert_eq!(BlockStatus::from_u8(6), Ok(BlockStatus::Imported));
        assert_eq!(BlockStatus::from_u8(7), Err(Error::InvalidStatus(7)));
        assert_eq!(BlockStatus::from_u8(255), Err(Error::InvalidStatus(255)));

        // Test round-trip conversions
        for &status in &[
            BlockStatus::Seen,
            BlockStatus::Processing,
            BlockStatus::Pending,
            BlockStatus::Executing,
            BlockStatus::Invalid,
            BlockStatus::Importing,
            BlockStatus::Imported,
        ] {
            assert_eq!(BlockStatus::from_u8(status.to_u8()), Ok(status));
        }
    }

    #[test]
    fn test_concurrent_cas_contention() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);
        let slot = Slot::new(1);
        table.insert(hash, slot, BlockStatus::Pending);

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
                    if table_clone
                        .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                        .is_ok()
                    {
                        successful_cas += 1;
                        // Immediately transition back to allow other threads to compete
                        assert!(
                            table_clone
                                .transition(&hash, BlockStatus::Executing, BlockStatus::Pending,)
                                .is_ok()
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
        let slot = Slot::new(1);

        // Insert pending block
        table.insert(hash, slot, BlockStatus::Pending);

        // Subscribe to updates
        let (current_status, mut rx) = table.subscribe(&hash).expect("Should be able to subscribe");
        assert_eq!(current_status, BlockStatus::Pending);

        // Transition to Executing
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                .is_ok()
        );

        // Should receive notification
        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Executing);

        // Transition to Importing
        assert!(
            table
                .transition(&hash, BlockStatus::Executing, BlockStatus::Importing)
                .is_ok()
        );

        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Importing);

        // Transition to Imported (terminal state)
        assert!(
            table
                .transition(&hash, BlockStatus::Importing, BlockStatus::Imported)
                .is_ok()
        );

        let status = rx.recv().await.expect("Should receive notification");
        assert_eq!(status, BlockStatus::Imported);
    }

    #[tokio::test]
    async fn test_subscribe_race_condition() {
        let table = Arc::new(BlockStatusTable::new());
        let hash = test_hash(1);
        let slot = Slot::new(1);

        table.insert(hash, slot, BlockStatus::Pending);

        // Spawn a task that will transition the status immediately
        let table_clone = Arc::clone(&table);
        let transition_handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            assert!(
                table_clone
                    .transition(&hash, BlockStatus::Pending, BlockStatus::Executing,)
                    .is_ok()
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
        let slot = Slot::new(1);

        table.insert(hash, slot, BlockStatus::Pending);

        // Create multiple subscribers
        let (status1, mut rx1) = table.subscribe(&hash).expect("Should subscribe");
        let (status2, mut rx2) = table.subscribe(&hash).expect("Should subscribe");
        let (status3, mut rx3) = table.subscribe(&hash).expect("Should subscribe");

        assert_eq!(status1, BlockStatus::Pending);
        assert_eq!(status2, BlockStatus::Pending);
        assert_eq!(status3, BlockStatus::Pending);

        // Transition state
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                .is_ok()
        );

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
        let slot = Slot::new(1);

        table.insert(hash, slot, BlockStatus::Pending);
        let (_status, mut rx) = table.subscribe(&hash).expect("Should subscribe");

        // Transition to terminal state and remove
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Imported)
                .is_ok()
        );

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
        let slot = Slot::new(1);

        table.insert(hash, slot, BlockStatus::Pending);

        // First subscriber
        let (_status1, mut rx1) = table.subscribe(&hash).expect("Should subscribe");

        // Transition through multiple states
        assert!(
            table
                .transition(&hash, BlockStatus::Pending, BlockStatus::Executing)
                .is_ok()
        );
        assert!(
            table
                .transition(&hash, BlockStatus::Executing, BlockStatus::Importing)
                .is_ok()
        );

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
        assert!(
            table
                .transition(&hash, BlockStatus::Importing, BlockStatus::Imported)
                .is_ok()
        );

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
*/

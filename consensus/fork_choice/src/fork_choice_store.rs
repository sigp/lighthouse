use types::{BeaconBlock, BeaconState, Checkpoint, EthSpec, Hash256, Slot};

/// Approximates the `Store` in "Ethereum 2.0 Phase 0 -- Beacon Chain Fork Choice":
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#store
///
/// ## Detail
///
/// This is only an approximation for two reasons:
///
/// - This crate stores the actual block DAG in `ProtoArrayForkChoice`.
/// - `time` is represented using `Slot` instead of UNIX epoch `u64`.
pub trait ForkChoiceStore<T: EthSpec>: Sized {
    type Error;
    /// Returns the last value passed to `Self::update_time`.
    fn get_current_slot(&self) -> Slot;

    /// Set the value to be returned by `Self::get_current_slot`.
    ///
    /// ## Notes
    ///
    /// This should only ever be called from within `ForkChoice::on_tick`.
    fn set_current_slot(&mut self, slot: Slot);

    /// Called whenever `ForkChoice::on_block` has processed a block. Allows the implementer to
    /// performing caching or other housekeeping duties.
    fn after_block(
        &mut self,
        block: &BeaconBlock<T>,
        block_root: Hash256,
        state: &BeaconState<T>,
    ) -> Result<(), Self::Error>;

    /// Updates the `justified_checkpoint` to the `best_justified_checkpoint`.
    ///
    /// ## Notes
    ///
    /// This should only ever be called from within the `Self::on_tick` implementation.
    ///
    /// *This method only exists as a public trait function to allow for a default `Self::on_tick`
    /// implementation.*
    ///
    /// ## Specification
    ///
    /// Implementation must be equivalent to:
    ///
    /// ```ignore
    /// store.justified_checkpoint = store.best_justified_checkpoint
    /// ```
    fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), Self::Error>;

    /// Returns the `justified_checkpoint`.
    fn justified_checkpoint(&self) -> &Checkpoint;

    /// Returns balances from the `state` identified by `justified_checkpoint.root`.
    fn justified_balances(&self) -> &[u64];

    /// Returns the `best_justified_checkpoint`.
    fn best_justified_checkpoint(&self) -> &Checkpoint;

    /// Returns the `finalized_checkpoint`.
    fn finalized_checkpoint(&self) -> &Checkpoint;

    /// Sets `finalized_checkpoint`.
    fn set_finalized_checkpoint(&mut self, c: Checkpoint);

    /// Sets the `justified_checkpoint`.
    fn set_justified_checkpoint(&mut self, state: &BeaconState<T>) -> Result<(), Self::Error>;

    /// Sets the `best_justified_checkpoint`.
    fn set_best_justified_checkpoint(&mut self, state: &BeaconState<T>);

    /// Returns the block root of an ancestor of `block_root` at the given `ancestor_slot`.
    fn ancestor_at_slot(
        &self,
        state: &BeaconState<T>,
        block_root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Hash256, Self::Error>;
}

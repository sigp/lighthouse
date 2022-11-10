use std::collections::BTreeSet;
use std::fmt::Debug;
use types::{BeaconBlockRef, BeaconState, Checkpoint, EthSpec, ExecPayload, Hash256, Slot};

/// Approximates the `Store` in "Ethereum 2.0 Phase 0 -- Beacon Chain Fork Choice":
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#store
///
/// ## Detail
///
/// This is only an approximation for two reasons:
///
/// - This crate stores the actual block DAG in `ProtoArrayForkChoice`.
/// - `time` is represented using `Slot` instead of UNIX epoch `u64`.
///
/// ## Motiviation
///
/// The primary motivation for defining this as a trait to be implemented upstream rather than a
/// concrete struct is to allow this crate to be free from "impure" on-disk database logic,
/// hopefully making auditing easier.
pub trait ForkChoiceStore<T: EthSpec>: Sized {
    type Error: Debug;

    /// Returns the last value passed to `Self::set_current_slot`.
    fn get_current_slot(&self) -> Slot;

    /// Set the value to be returned by `Self::get_current_slot`.
    ///
    /// ## Notes
    ///
    /// This should only ever be called from within `ForkChoice::on_tick`.
    fn set_current_slot(&mut self, slot: Slot);

    /// Called whenever `ForkChoice::on_block` has verified a block, but not yet added it to fork
    /// choice. Allows the implementer to performing caching or other housekeeping duties.
    fn on_verified_block<Payload: ExecPayload<T>>(
        &mut self,
        block: BeaconBlockRef<T, Payload>,
        block_root: Hash256,
        state: &BeaconState<T>,
    ) -> Result<(), Self::Error>;

    /// Returns the `justified_checkpoint`.
    fn justified_checkpoint(&self) -> &Checkpoint;

    /// Returns balances from the `state` identified by `justified_checkpoint.root`.
    fn justified_balances(&self) -> &[u64];

    /// Returns the `best_justified_checkpoint`.
    fn best_justified_checkpoint(&self) -> &Checkpoint;

    /// Returns the `finalized_checkpoint`.
    fn finalized_checkpoint(&self) -> &Checkpoint;

    /// Returns the `unrealized_justified_checkpoint`.
    fn unrealized_justified_checkpoint(&self) -> &Checkpoint;

    /// Returns the `unrealized_finalized_checkpoint`.
    fn unrealized_finalized_checkpoint(&self) -> &Checkpoint;

    /// Returns the `proposer_boost_root`.
    fn proposer_boost_root(&self) -> Hash256;

    /// Sets `finalized_checkpoint`.
    fn set_finalized_checkpoint(&mut self, checkpoint: Checkpoint);

    /// Sets the `justified_checkpoint`.
    fn set_justified_checkpoint(&mut self, checkpoint: Checkpoint) -> Result<(), Self::Error>;

    /// Sets the `best_justified_checkpoint`.
    fn set_best_justified_checkpoint(&mut self, checkpoint: Checkpoint);

    /// Sets the `unrealized_justified_checkpoint`.
    fn set_unrealized_justified_checkpoint(&mut self, checkpoint: Checkpoint);

    /// Sets the `unrealized_finalized_checkpoint`.
    fn set_unrealized_finalized_checkpoint(&mut self, checkpoint: Checkpoint);

    /// Sets the proposer boost root.
    fn set_proposer_boost_root(&mut self, proposer_boost_root: Hash256);

    /// Gets the equivocating indices.
    fn equivocating_indices(&self) -> &BTreeSet<u64>;

    /// Adds to the set of equivocating indices.
    fn extend_equivocating_indices(&mut self, indices: impl IntoIterator<Item = u64>);
}

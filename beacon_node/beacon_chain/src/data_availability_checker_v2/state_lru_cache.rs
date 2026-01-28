use crate::payload_verification_types::{AvailabilityPendingExecutedPayload, PayloadImportData};
use crate::{
    BeaconChainTypes, BeaconStore, PayloadVerificationOutcome,
    data_availability_checker_v2::{AvailabilityCheckError, STATE_LRU_CAPACITY_NON_ZERO},
};
use lru::LruCache;
use parking_lot::RwLock;
use std::sync::Arc;
use store::OnDiskConsensusContext;
use tracing::{Span, instrument};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, Hash256, SignedExecutionPayloadEnvelope};

/// This mirrors everything in the `AvailabilityPendingExecutedBlock`, except
/// that it is much smaller because it contains only a state root instead of
/// a full `BeaconState`.
#[derive(Clone)]
pub struct DietAvailabilityPendingExecutedPayload<E: EthSpec> {
    payload: Arc<SignedExecutionPayloadEnvelope<E>>,
    state_root: Hash256,
    consensus_context: OnDiskConsensusContext<E>,
    payload_verification_outcome: PayloadVerificationOutcome,
}

/// Implementing the same methods as `AvailabilityPendingExecutedPayload`
impl<E: EthSpec> DietAvailabilityPendingExecutedPayload<E> {
    pub fn as_payload(&self) -> &SignedExecutionPayloadEnvelope<E> {
        &self.payload
    }

    pub fn payload_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<E>> {
        self.payload.clone()
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.payload.message.blob_kzg_commitments.len()
    }
}

/// This LRU cache holds BeaconStates used for payload import. If the cache overflows,
/// the least recently used state will be dropped. If the dropped state is needed
/// later on, it will be recovered from the parent state and replaying the payload.
///
/// WARNING: This cache assumes the parent block of any `AvailabilityPendingExecutedPayload`
/// has already been imported into ForkChoice. If this is not the case, the cache
/// will fail to recover the state when the cache overflows because it can't load
/// the parent state!
pub struct StateLRUCache<T: BeaconChainTypes> {
    states: RwLock<LruCache<Hash256, BeaconState<T::EthSpec>>>,
    store: BeaconStore<T>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> StateLRUCache<T> {
    pub fn new(store: BeaconStore<T>, spec: Arc<ChainSpec>) -> Self {
        Self {
            states: RwLock::new(LruCache::new(STATE_LRU_CAPACITY_NON_ZERO)),
            store,
            spec,
        }
    }

    /// This will store the state in the LRU cache and return a
    /// `DietAvailabilityPendingExecutedPayload` which is much cheaper to
    /// keep around in memory.
    pub fn register_pending_executed_payload(
        &self,
        executed_payload: AvailabilityPendingExecutedPayload<T::EthSpec>,
    ) -> DietAvailabilityPendingExecutedPayload<T::EthSpec> {
        let state = executed_payload.import_data.state;
        let state_root = executed_payload.payload.message.state_root;
        self.states.write().put(state_root, state);

        DietAvailabilityPendingExecutedPayload {
            payload: executed_payload.payload,
            state_root,
            consensus_context: OnDiskConsensusContext::from_consensus_context(
                executed_payload.import_data.consensus_context,
            ),
            payload_verification_outcome: executed_payload.payload_verification_outcome,
        }
    }

    /// Recover the `AvailabilityPendingExecutedPayload` from the diet version.
    /// This method will first check the cache and if the state is not found
    /// it will reconstruct the state by loading the parent state from disk and
    /// replaying the block.
    #[instrument(skip_all, parent = _span, level = "debug")]
    pub fn recover_pending_executed_payload(
        &self,
        diet_executed_payload: DietAvailabilityPendingExecutedPayload<T::EthSpec>,
        _span: &Span,
    ) -> Result<AvailabilityPendingExecutedPayload<T::EthSpec>, AvailabilityCheckError> {
        // Keep the state in the cache to prevent reconstruction in race conditions
        let state = if let Some(state) = self.states.write().get(&diet_executed_payload.state_root)
        {
            state.clone()
        } else {
            self.reconstruct_state(&diet_executed_payload)?
        };
        Ok(AvailabilityPendingExecutedPayload {
            payload: diet_executed_payload.payload,
            import_data: PayloadImportData {
                state,
                consensus_context: diet_executed_payload
                    .consensus_context
                    .into_consensus_context(),
            },
            payload_verification_outcome: diet_executed_payload.payload_verification_outcome,
        })
    }

    /// Reconstruct the state by loading the parent state from disk and replaying
    /// the block.
    #[instrument(skip_all, level = "debug")]
    fn reconstruct_state(
        &self,
        diet_executed_block: &DietAvailabilityPendingExecutedPayload<T::EthSpec>,
    ) -> Result<BeaconState<T::EthSpec>, AvailabilityCheckError> {
        todo!()
    }

    /// returns the state cache for inspection
    pub fn lru_cache(&self) -> &RwLock<LruCache<Hash256, BeaconState<T::EthSpec>>> {
        &self.states
    }

    /// remove any states from the cache from before the given epoch
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) {
        let mut write_lock = self.states.write();
        while let Some((_, state)) = write_lock.peek_lru() {
            if state.slot().epoch(T::EthSpec::slots_per_epoch()) < cutoff_epoch {
                write_lock.pop_lru();
            } else {
                break;
            }
        }
    }
}

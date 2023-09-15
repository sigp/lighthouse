use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{
    BlockPackingEfficiency, BlockPackingEfficiencyQuery, ProposerInfo, UniqueAttestation,
};
use parking_lot::Mutex;
use state_processing::{
    per_epoch_processing::EpochProcessingSummary, BlockReplayError, BlockReplayer,
};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{
    BeaconCommittee, BeaconState, BeaconStateError, BlindedPayload, ChainSpec, Epoch, EthSpec,
    Hash256, OwnedBeaconCommittee, RelativeEpoch, SignedBeaconBlock, Slot,
};
use warp_utils::reject::{beacon_chain_error, custom_bad_request, custom_server_error};

/// Load blocks from block roots in chunks to reduce load on memory.
const BLOCK_ROOT_CHUNK_SIZE: usize = 100;

#[derive(Debug)]
enum PackingEfficiencyError {
    BlockReplay(BlockReplayError),
    BeaconState(BeaconStateError),
    CommitteeStoreError(Slot),
    InvalidAttestationError,
}

impl From<BlockReplayError> for PackingEfficiencyError {
    fn from(e: BlockReplayError) -> Self {
        Self::BlockReplay(e)
    }
}

impl From<BeaconStateError> for PackingEfficiencyError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

struct CommitteeStore {
    current_epoch_committees: Vec<OwnedBeaconCommittee>,
    previous_epoch_committees: Vec<OwnedBeaconCommittee>,
}

impl CommitteeStore {
    fn new() -> Self {
        CommitteeStore {
            current_epoch_committees: Vec::new(),
            previous_epoch_committees: Vec::new(),
        }
    }
}

struct PackingEfficiencyHandler<T: EthSpec> {
    current_slot: Slot,
    current_epoch: Epoch,
    prior_skip_slots: u64,
    available_attestations: HashSet<UniqueAttestation>,
    included_attestations: HashMap<UniqueAttestation, u64>,
    committee_store: CommitteeStore,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> PackingEfficiencyHandler<T> {
    fn new(
        start_epoch: Epoch,
        starting_state: BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<Self, PackingEfficiencyError> {
        let mut handler = PackingEfficiencyHandler {
            current_slot: start_epoch.start_slot(T::slots_per_epoch()),
            current_epoch: start_epoch,
            prior_skip_slots: 0,
            available_attestations: HashSet::new(),
            included_attestations: HashMap::new(),
            committee_store: CommitteeStore::new(),
            _phantom: PhantomData,
        };

        handler.compute_epoch(start_epoch, &starting_state, spec)?;
        Ok(handler)
    }

    fn update_slot(&mut self, slot: Slot) {
        self.current_slot = slot;
        if slot % T::slots_per_epoch() == 0 {
            self.current_epoch = Epoch::new(slot.as_u64() / T::slots_per_epoch());
        }
    }

    fn prune_included_attestations(&mut self) {
        let epoch = self.current_epoch;
        self.included_attestations.retain(|x, _| {
            x.slot >= Epoch::new(epoch.as_u64().saturating_sub(2)).start_slot(T::slots_per_epoch())
        });
    }

    fn prune_available_attestations(&mut self) {
        let slot = self.current_slot;
        self.available_attestations
            .retain(|x| x.slot >= (slot.as_u64().saturating_sub(T::slots_per_epoch())));
    }

    fn apply_block(
        &mut self,
        block: &SignedBeaconBlock<T, BlindedPayload<T>>,
    ) -> Result<usize, PackingEfficiencyError> {
        let block_body = block.message().body();
        let attestations = block_body.attestations();

        let mut attestations_in_block = HashMap::new();
        for attestation in attestations.iter() {
            for (position, voted) in attestation.aggregation_bits.iter().enumerate() {
                if voted {
                    let unique_attestation = UniqueAttestation {
                        slot: attestation.data.slot,
                        committee_index: attestation.data.index,
                        committee_position: position,
                    };
                    let inclusion_distance: u64 = block
                        .slot()
                        .as_u64()
                        .checked_sub(attestation.data.slot.as_u64())
                        .ok_or(PackingEfficiencyError::InvalidAttestationError)?;

                    self.available_attestations.remove(&unique_attestation);
                    attestations_in_block.insert(unique_attestation, inclusion_distance);
                }
            }
        }

        // Remove duplicate attestations as these yield no reward.
        attestations_in_block.retain(|x, _| self.included_attestations.get(x).is_none());
        self.included_attestations
            .extend(attestations_in_block.clone());

        Ok(attestations_in_block.len())
    }

    fn add_attestations(&mut self, slot: Slot) -> Result<(), PackingEfficiencyError> {
        let committees = self.get_committees_at_slot(slot)?;
        for committee in committees {
            for position in 0..committee.committee.len() {
                let unique_attestation = UniqueAttestation {
                    slot,
                    committee_index: committee.index,
                    committee_position: position,
                };
                self.available_attestations.insert(unique_attestation);
            }
        }

        Ok(())
    }

    fn compute_epoch(
        &mut self,
        epoch: Epoch,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<(), PackingEfficiencyError> {
        // Free some memory by pruning old attestations from the included set.
        self.prune_included_attestations();

        let new_committees = if state.committee_cache_is_initialized(RelativeEpoch::Current) {
            state
                .get_beacon_committees_at_epoch(RelativeEpoch::Current)?
                .into_iter()
                .map(BeaconCommittee::into_owned)
                .collect::<Vec<_>>()
        } else {
            state
                .initialize_committee_cache(epoch, spec)?
                .get_all_beacon_committees()?
                .into_iter()
                .map(BeaconCommittee::into_owned)
                .collect::<Vec<_>>()
        };

        self.committee_store.previous_epoch_committees =
            self.committee_store.current_epoch_committees.clone();

        self.committee_store.current_epoch_committees = new_committees;

        Ok(())
    }

    fn get_committees_at_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<OwnedBeaconCommittee>, PackingEfficiencyError> {
        let mut committees = Vec::new();

        for committee in &self.committee_store.current_epoch_committees {
            if committee.slot == slot {
                committees.push(committee.clone());
            }
        }
        for committee in &self.committee_store.previous_epoch_committees {
            if committee.slot == slot {
                committees.push(committee.clone());
            }
        }

        if committees.is_empty() {
            return Err(PackingEfficiencyError::CommitteeStoreError(slot));
        }

        Ok(committees)
    }
}

pub fn get_block_packing_efficiency<T: BeaconChainTypes>(
    query: BlockPackingEfficiencyQuery,
    chain: Arc<BeaconChain<T>>,
) -> Result<Vec<BlockPackingEfficiency>, warp::Rejection> {
    let spec = &chain.spec;

    let start_epoch = query.start_epoch;
    let start_slot = start_epoch.start_slot(T::EthSpec::slots_per_epoch());
    let prior_slot = start_slot - 1;

    let end_epoch = query.end_epoch;
    let end_slot = end_epoch.end_slot(T::EthSpec::slots_per_epoch());

    // Check query is valid.
    if start_epoch > end_epoch || start_epoch == 0 {
        return Err(custom_bad_request(format!(
            "invalid start and end epochs: {}, {}",
            start_epoch, end_epoch
        )));
    }

    let prior_epoch = start_epoch - 1;
    let start_slot_of_prior_epoch = prior_epoch.start_slot(T::EthSpec::slots_per_epoch());

    // Load block roots.
    let mut block_roots: Vec<Hash256> = chain
        .forwards_iter_block_roots_until(start_slot_of_prior_epoch, end_slot)
        .map_err(beacon_chain_error)?
        .collect::<Result<Vec<(Hash256, Slot)>, _>>()
        .map_err(beacon_chain_error)?
        .iter()
        .map(|(root, _)| *root)
        .collect();
    block_roots.dedup();

    let first_block_root = block_roots
        .first()
        .ok_or_else(|| custom_server_error("no blocks were loaded".to_string()))?;

    let first_block = chain
        .get_blinded_block(first_block_root)
        .and_then(|maybe_block| {
            maybe_block.ok_or(BeaconChainError::MissingBeaconBlock(*first_block_root))
        })
        .map_err(beacon_chain_error)?;

    // Load state for block replay.
    let starting_state_root = first_block.state_root();

    let starting_state = chain
        .get_state(&starting_state_root, Some(prior_slot))
        .and_then(|maybe_state| {
            maybe_state.ok_or(BeaconChainError::MissingBeaconState(starting_state_root))
        })
        .map_err(beacon_chain_error)?;

    // Initialize response vector.
    let mut response = Vec::new();

    // Initialize handler.
    let handler = Arc::new(Mutex::new(
        PackingEfficiencyHandler::new(prior_epoch, starting_state.clone(), spec)
            .map_err(|e| custom_server_error(format!("{:?}", e)))?,
    ));

    let pre_slot_hook =
        |state: &mut BeaconState<T::EthSpec>| -> Result<(), PackingEfficiencyError> {
            // Add attestations to `available_attestations`.
            handler.lock().add_attestations(state.slot())?;
            Ok(())
        };

    let post_slot_hook = |state: &mut BeaconState<T::EthSpec>,
                          _summary: Option<EpochProcessingSummary<T::EthSpec>>,
                          is_skip_slot: bool|
     -> Result<(), PackingEfficiencyError> {
        handler.lock().update_slot(state.slot());

        // Check if this a new epoch.
        if state.slot() % T::EthSpec::slots_per_epoch() == 0 {
            handler.lock().compute_epoch(
                state.slot().epoch(T::EthSpec::slots_per_epoch()),
                state,
                spec,
            )?;
        }

        if is_skip_slot {
            handler.lock().prior_skip_slots += 1;
        }

        // Remove expired attestations.
        handler.lock().prune_available_attestations();

        Ok(())
    };

    let pre_block_hook = |_state: &mut BeaconState<T::EthSpec>,
                          block: &SignedBeaconBlock<_, BlindedPayload<_>>|
     -> Result<(), PackingEfficiencyError> {
        let slot = block.slot();

        let block_message = block.message();
        // Get block proposer info.
        let proposer_info = ProposerInfo {
            validator_index: block_message.proposer_index(),
            graffiti: block_message.body().graffiti().as_utf8_lossy(),
        };

        // Store the count of available attestations at this point.
        // In the future it may be desirable to check that the number of available attestations
        // does not exceed the maximum possible amount given the length of available committees.
        let available_count = handler.lock().available_attestations.len();

        // Get all attestations included in the block.
        let included = handler.lock().apply_block(block)?;

        let efficiency = BlockPackingEfficiency {
            slot,
            block_hash: block.canonical_root(),
            proposer_info,
            available_attestations: available_count,
            included_attestations: included,
            prior_skip_slots: handler.lock().prior_skip_slots,
        };

        // Write to response.
        if slot >= start_slot {
            response.push(efficiency);
        }

        handler.lock().prior_skip_slots = 0;

        Ok(())
    };

    // Build BlockReplayer.
    let mut replayer = BlockReplayer::new(starting_state, spec)
        .no_state_root_iter()
        .no_signature_verification()
        .minimal_block_root_verification()
        .pre_slot_hook(Box::new(pre_slot_hook))
        .post_slot_hook(Box::new(post_slot_hook))
        .pre_block_hook(Box::new(pre_block_hook));

    // Iterate through the block roots, loading blocks in chunks to reduce load on memory.
    for block_root_chunks in block_roots.chunks(BLOCK_ROOT_CHUNK_SIZE) {
        // Load blocks from the block root chunks.
        let blocks = block_root_chunks
            .iter()
            .map(|root| {
                chain
                    .get_blinded_block(root)
                    .and_then(|maybe_block| {
                        maybe_block.ok_or(BeaconChainError::MissingBeaconBlock(*root))
                    })
                    .map_err(beacon_chain_error)
            })
            .collect::<Result<Vec<_>, _>>()?;

        replayer = replayer
            .apply_blocks(blocks, None)
            .map_err(|e: PackingEfficiencyError| custom_server_error(format!("{:?}", e)))?;
    }

    drop(replayer);

    Ok(response)
}

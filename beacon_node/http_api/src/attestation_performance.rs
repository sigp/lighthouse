use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::lighthouse::{
    AttestationPerformance, AttestationPerformanceQuery, AttestationPerformanceStatistics,
};
use state_processing::{
    per_epoch_processing::altair::participation_cache::Error as ParticipationCacheError,
    per_epoch_processing::EpochProcessingSummary, BlockReplayError, BlockReplayer,
};
use std::sync::Arc;
use types::{BeaconState, BeaconStateError, EthSpec, Hash256};
use warp_utils::reject::{beacon_chain_error, custom_bad_request, custom_server_error};

const MAX_REQUEST_RANGE_EPOCHS: usize = 100;
const BLOCK_ROOT_CHUNK_SIZE: usize = 100;

#[derive(Debug)]
enum AttestationPerformanceError {
    BlockReplay(BlockReplayError),
    BeaconState(BeaconStateError),
    ParticipationCache(ParticipationCacheError),
    UnableToFindValidator(usize),
}

impl From<BlockReplayError> for AttestationPerformanceError {
    fn from(e: BlockReplayError) -> Self {
        Self::BlockReplay(e)
    }
}

impl From<BeaconStateError> for AttestationPerformanceError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<ParticipationCacheError> for AttestationPerformanceError {
    fn from(e: ParticipationCacheError) -> Self {
        Self::ParticipationCache(e)
    }
}

pub fn get_attestation_performance<T: BeaconChainTypes>(
    target: String,
    query: AttestationPerformanceQuery,
    chain: Arc<BeaconChain<T>>,
) -> Result<Vec<AttestationPerformance>, warp::Rejection> {
    let spec = &chain.spec;
    // We increment by 2 here so that when we build the state from the `prior_slot` it is
    // still 1 epoch ahead of the first epoch we want to analyse.
    // This ensures the `.is_previous_epoch_X` functions on `EpochProcessingSummary` return results
    // for the correct epoch.
    let start_epoch = query.start_epoch + 2;
    let start_slot = start_epoch.start_slot(T::EthSpec::slots_per_epoch());
    let prior_slot = start_slot - 1;

    let end_epoch = query.end_epoch + 2;
    let end_slot = end_epoch.end_slot(T::EthSpec::slots_per_epoch());

    // Ensure end_epoch is smaller than the current epoch - 1.
    let current_epoch = chain.epoch().map_err(beacon_chain_error)?;
    if query.end_epoch >= current_epoch - 1 {
        return Err(custom_bad_request(format!(
            "end_epoch must be less than the current epoch - 1. current: {}, end: {}",
            current_epoch, query.end_epoch
        )));
    }

    // Check query is valid.
    if start_epoch > end_epoch {
        return Err(custom_bad_request(format!(
            "start_epoch must not be larger than end_epoch. start: {}, end: {}",
            query.start_epoch, query.end_epoch
        )));
    }

    // The response size can grow exceptionally large therefore we should check that the
    // query is within permitted bounds to prevent potential OOM errors.
    if (end_epoch - start_epoch).as_usize() > MAX_REQUEST_RANGE_EPOCHS {
        return Err(custom_bad_request(format!(
            "end_epoch must not exceed start_epoch by more than 100 epochs. start: {}, end: {}",
            query.start_epoch, query.end_epoch
        )));
    }

    // Either use the global validator set, or the specified index.
    //
    // Does no further validation of the indices, so in the event an index has not yet been
    // activated or does not yet exist (according to the head state), it will return all fields as
    // `false`.
    let index_range = if target.to_lowercase() == "global" {
        chain
            .with_head(|head| Ok((0..head.beacon_state.validators().len() as u64).collect()))
            .map_err(beacon_chain_error)?
    } else {
        vec![target.parse::<u64>().map_err(|_| {
            custom_bad_request(format!(
                "Invalid validator index: {:?}",
                target.to_lowercase()
            ))
        })?]
    };

    // Load block roots.
    let mut block_roots: Vec<Hash256> = chain
        .forwards_iter_block_roots_until(start_slot, end_slot)
        .map_err(beacon_chain_error)?
        .map(|res| res.map(|(root, _)| root))
        .collect::<Result<Vec<Hash256>, _>>()
        .map_err(beacon_chain_error)?;
    block_roots.dedup();

    // Load first block so we can get its parent.
    let first_block_root = block_roots.first().ok_or_else(|| {
        custom_server_error(
            "No blocks roots could be loaded. Ensure the beacon node is synced.".to_string(),
        )
    })?;
    let first_block = chain
        .get_blinded_block(first_block_root)
        .and_then(|maybe_block| {
            maybe_block.ok_or(BeaconChainError::MissingBeaconBlock(*first_block_root))
        })
        .map_err(beacon_chain_error)?;

    // Load the block of the prior slot which will be used to build the starting state.
    let prior_block = chain
        .get_blinded_block(&first_block.parent_root())
        .and_then(|maybe_block| {
            maybe_block
                .ok_or_else(|| BeaconChainError::MissingBeaconBlock(first_block.parent_root()))
        })
        .map_err(beacon_chain_error)?;

    // Load state for block replay.
    let state_root = prior_block.state_root();
    let state = chain
        .get_state(&state_root, Some(prior_slot))
        .and_then(|maybe_state| maybe_state.ok_or(BeaconChainError::MissingBeaconState(state_root)))
        .map_err(beacon_chain_error)?;

    // Allocate an AttestationPerformance vector for each validator in the range.
    let mut perfs: Vec<AttestationPerformance> =
        AttestationPerformance::initialize(index_range.clone());

    let post_slot_hook = |state: &mut BeaconState<T::EthSpec>,
                          summary: Option<EpochProcessingSummary<T::EthSpec>>,
                          _is_skip_slot: bool|
     -> Result<(), AttestationPerformanceError> {
        // If a `summary` was not output then an epoch boundary was not crossed
        // so we move onto the next slot.
        if let Some(summary) = summary {
            for (position, i) in index_range.iter().enumerate() {
                let index = *i as usize;

                let val = perfs
                    .get_mut(position)
                    .ok_or(AttestationPerformanceError::UnableToFindValidator(index))?;

                // We are two epochs ahead since the summary is generated for
                // `state.previous_epoch()` then `summary.is_previous_epoch_X` functions return
                // data for the epoch before that.
                let epoch = state.previous_epoch().as_u64() - 1;

                let is_active = summary.is_active_unslashed_in_previous_epoch(index);

                let received_source_reward = summary.is_previous_epoch_source_attester(index)?;

                let received_head_reward = summary.is_previous_epoch_head_attester(index)?;

                let received_target_reward = summary.is_previous_epoch_target_attester(index)?;

                let inclusion_delay = summary
                    .previous_epoch_inclusion_info(index)
                    .map(|info| info.delay);

                let perf = AttestationPerformanceStatistics {
                    active: is_active,
                    head: received_head_reward,
                    target: received_target_reward,
                    source: received_source_reward,
                    delay: inclusion_delay,
                };

                val.epochs.insert(epoch, perf);
            }
        }
        Ok(())
    };

    // Initialize block replayer
    let mut replayer = BlockReplayer::new(state, spec)
        .no_state_root_iter()
        .no_signature_verification()
        .minimal_block_root_verification()
        .post_slot_hook(Box::new(post_slot_hook));

    // Iterate through block roots in chunks to reduce load on memory.
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
            .map_err(|e| custom_server_error(format!("{:?}", e)))?;
    }

    drop(replayer);

    Ok(perfs)
}

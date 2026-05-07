use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

use bls::{PublicKeyBytes, Signature};
use execution_layer::{
    BlockProposalContentsGloas, BuilderParams, PayloadAttributes, PayloadParameters,
};
use fork_choice::PayloadStatus;
use operation_pool::CompactAttestationRef;
use ssz::Encode;
use state_processing::common::{get_attesting_indices_from_state, get_indexed_payload_attestation};
use state_processing::envelope_processing::verify_execution_payload_envelope;
use state_processing::epoch_cache::initialize_epoch_cache;
use state_processing::per_block_processing::is_valid_indexed_payload_attestation;
use state_processing::per_block_processing::{
    apply_parent_execution_payload, compute_timestamp_at_slot, get_expected_withdrawals,
    verify_attestation_for_block_inclusion,
};
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
};
use state_processing::{VerifyOperation, state_advance::complete_state_advance};
use task_executor::JoinHandle;
use tracing::{Instrument, debug, debug_span, error, instrument, trace, warn};
use tree_hash::TreeHash;
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::{
    Address, Attestation, AttestationElectra, AttesterSlashing, AttesterSlashingElectra,
    BeaconBlock, BeaconBlockBodyGloas, BeaconBlockGloas, BeaconState, BeaconStateError,
    BuilderIndex, ChainSpec, Deposit, Eth1Data, EthSpec, ExecutionBlockHash, ExecutionPayloadBid,
    ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequests, FullPayload, Graffiti,
    Hash256, PayloadAttestation, ProposerSlashing, RelativeEpoch, SignedBeaconBlock,
    SignedBlsToExecutionChange, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    SignedVoluntaryExit, Slot, SyncAggregate, Withdrawal, Withdrawals,
};

use crate::pending_payload_envelopes::PendingEnvelopeData;
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError,
    ProduceBlockVerification, block_production::BlockProductionState,
    graffiti_calculator::GraffitiSettings, metrics,
};

pub const BID_VALUE_SELF_BUILD: u64 = 0;
pub const EXECUTION_PAYMENT_TRUSTLESS_BUILD: u64 = 0;

type ConsensusBlockValue = u64;
type BlockProductionResult<E> = (BeaconBlock<E>, BeaconState<E>, ConsensusBlockValue);

pub type PreparePayloadResult<E> = Result<BlockProposalContentsGloas<E>, BlockProductionError>;
pub type PreparePayloadHandle<E> = JoinHandle<Option<PreparePayloadResult<E>>>;

pub struct PartialBeaconBlock<E: EthSpec> {
    slot: Slot,
    proposer_index: u64,
    parent_root: Hash256,
    randao_reveal: Signature,
    eth1_data: Eth1Data,
    graffiti: Graffiti,
    proposer_slashings: Vec<ProposerSlashing>,
    attester_slashings: Vec<AttesterSlashingElectra<E>>,
    attestations: Vec<AttestationElectra<E>>,
    payload_attestations: Vec<PayloadAttestation<E>>,
    deposits: Vec<Deposit>,
    voluntary_exits: Vec<SignedVoluntaryExit>,
    sync_aggregate: SyncAggregate<E>,
    bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
}

/// Data needed to construct an ExecutionPayloadEnvelope.
/// The envelope requires the beacon_block_root which can only be computed after the block exists.
pub struct ExecutionPayloadData<E: types::EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequests<E>,
    pub builder_index: BuilderIndex,
    pub slot: Slot,
    pub blobs_and_proofs: (types::BlobsList<E>, types::KzgProofs<E>),
}

/// The result of a local payload build, used to decide whether to include a builder bid
/// from the gossip cache or fall back to self-build.
pub struct LocalBuildResult<E: EthSpec> {
    pub payload_data: ExecutionPayloadData<E>,
    /// EL block value (in wei) of the locally-built payload.
    pub payload_value: types::Uint256,
    /// `true` if the EL signaled `engine_getPayload`'s `shouldOverrideBuilder` flag.
    pub should_override_builder: bool,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn produce_block_with_verification_gloas(
        self: &Arc<Self>,
        randao_reveal: Signature,
        slot: Slot,
        graffiti_settings: GraffitiSettings,
        verification: ProduceBlockVerification,
        builder_boost_factor: Option<u64>,
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let _complete_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);
        // Part 1/2 (blocking)
        //
        // Load the parent state from disk.
        let chain = self.clone();
        let block_production_state = self
            .task_executor
            .spawn_blocking_handle(
                move || chain.load_state_for_block_production(slot),
                "load_state_for_block_production",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;
        let BlockProductionState {
            state,
            state_root: state_root_opt,
            parent_payload_status,
            parent_envelope,
        } = block_production_state;

        // Part 2/2 (async, with some blocking components)
        //
        // Produce the block upon the state
        self.produce_block_on_state_gloas(
            state,
            state_root_opt,
            parent_payload_status,
            parent_envelope,
            slot,
            randao_reveal,
            graffiti_settings,
            verification,
            builder_boost_factor,
        )
        .await
    }

    #[instrument(level = "debug", skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn produce_block_on_state_gloas(
        self: &Arc<Self>,
        state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        parent_payload_status: PayloadStatus,
        parent_envelope: Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        graffiti_settings: GraffitiSettings,
        verification: ProduceBlockVerification,
        builder_boost_factor: Option<u64>,
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        // Extract the parent's execution requests from the envelope (if parent was full).
        let parent_execution_requests = if parent_payload_status == PayloadStatus::Full {
            parent_envelope
                .as_ref()
                .map(|env| env.message.execution_requests.clone())
                .ok_or(BlockProductionError::MissingParentExecutionPayload)?
        } else {
            ExecutionRequests::default()
        };

        // Part 1/3 (blocking)
        //
        // Perform the state advance and block-packing functions.
        let chain = self.clone();
        let graffiti = self
            .graffiti_calculator
            .get_graffiti(graffiti_settings)
            .await;
        let parent_execution_requests_ref = parent_execution_requests.clone();
        let (partial_beacon_block, state) = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    chain.produce_partial_beacon_block_gloas(
                        state,
                        state_root_opt,
                        produce_at_slot,
                        randao_reveal,
                        graffiti,
                        &parent_execution_requests_ref,
                    )
                },
                "produce_partial_beacon_block_gloas",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        // Part 2/3 (async)
        //
        // Produce a local execution payload bid, then select between it and any cached
        // gossip-verified builder bid using `builder_boost_factor`.
        // TODO(gloas) build out trustless/trusted bid paths.
        let (local_signed_bid, state, local_build) = self
            .clone()
            .produce_execution_payload_bid(
                state,
                parent_payload_status,
                parent_envelope,
                produce_at_slot,
                BID_VALUE_SELF_BUILD,
                BUILDER_INDEX_SELF_BUILD,
            )
            .await?;

        let (execution_payload_bid, payload_data) =
            self.select_payload_bid(local_signed_bid, local_build, builder_boost_factor);

        // Part 3/3 (blocking)
        //
        // Complete the block with the execution payload bid.
        let chain = self.clone();
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    chain.complete_partial_beacon_block_gloas(
                        partial_beacon_block,
                        execution_payload_bid,
                        parent_execution_requests,
                        payload_data,
                        state,
                        verification,
                    )
                },
                "complete_partial_beacon_block_gloas",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)?
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[instrument(skip_all, level = "debug")]
    fn produce_partial_beacon_block_gloas(
        self: &Arc<Self>,
        mut state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        graffiti: Graffiti,
        parent_execution_requests: &ExecutionRequests<T::EthSpec>,
    ) -> Result<(PartialBeaconBlock<T::EthSpec>, BeaconState<T::EthSpec>), BlockProductionError>
    {
        // It is invalid to try to produce a block using a state from a future slot.
        if state.slot() > produce_at_slot {
            return Err(BlockProductionError::StateSlotTooHigh {
                produce_at_slot,
                state_slot: state.slot(),
            });
        }

        let slot_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_SLOT_PROCESS_TIMES);

        // Ensure the state has performed a complete transition into the required slot.
        complete_state_advance(&mut state, state_root_opt, produce_at_slot, &self.spec)?;

        drop(slot_timer);

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        state.apply_pending_mutations()?;

        let parent_root = if state.slot() > 0 {
            *state
                .get_block_root(state.slot() - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header().canonical_root()
        };

        let proposer_index = state.get_beacon_proposer_index(state.slot(), &self.spec)? as u64;

        let slashings_and_exits_span = debug_span!("get_slashings_and_exits").entered();
        let (mut proposer_slashings, mut attester_slashings, mut voluntary_exits) =
            self.op_pool.get_slashings_and_exits(&state, &self.spec);

        filter_voluntary_exits_for_parent_execution_requests(
            &mut voluntary_exits,
            parent_execution_requests,
            |idx| state.validators().get(idx as usize).map(|v| v.pubkey),
            &self.spec,
        );

        drop(slashings_and_exits_span);

        let eth1_data = state.eth1_data().clone();

        let deposits = vec![];

        let bls_changes_span = debug_span!("get_bls_to_execution_changes").entered();
        let bls_to_execution_changes = self
            .op_pool
            .get_bls_to_execution_changes(&state, &self.spec);
        drop(bls_changes_span);

        // Iterate through the naive aggregation pool and ensure all the attestations from there
        // are included in the operation pool.
        {
            let _guard = debug_span!("import_naive_aggregation_pool").entered();
            let _unagg_import_timer =
                metrics::start_timer(&metrics::BLOCK_PRODUCTION_UNAGGREGATED_TIMES);
            for attestation in self.naive_aggregation_pool.read().iter() {
                let import = |attestation: &Attestation<T::EthSpec>| {
                    let attesting_indices =
                        get_attesting_indices_from_state(&state, attestation.to_ref())?;
                    self.op_pool
                        .insert_attestation(attestation.clone(), attesting_indices)
                };
                if let Err(e) = import(attestation) {
                    // Don't stop block production if there's an error, just create a log.
                    error!(
                        reason = ?e,
                        "Attestation did not transfer to op pool"
                    );
                }
            }
        };

        let mut attestations = {
            let _guard = debug_span!("pack_attestations").entered();
            let _attestation_packing_timer =
                metrics::start_timer(&metrics::BLOCK_PRODUCTION_ATTESTATION_TIMES);

            // Epoch cache and total balance cache are required for op pool packing.
            state.build_total_active_balance_cache(&self.spec)?;
            initialize_epoch_cache(&mut state, &self.spec)?;

            let mut prev_filter_cache = HashMap::new();
            let prev_attestation_filter = |att: &CompactAttestationRef<T::EthSpec>| {
                self.filter_op_pool_attestation(&mut prev_filter_cache, att, &state)
            };
            let mut curr_filter_cache = HashMap::new();
            let curr_attestation_filter = |att: &CompactAttestationRef<T::EthSpec>| {
                self.filter_op_pool_attestation(&mut curr_filter_cache, att, &state)
            };

            self.op_pool
                .get_attestations(
                    &state,
                    prev_attestation_filter,
                    curr_attestation_filter,
                    &self.spec,
                )
                .map_err(BlockProductionError::OpPoolError)?
        };

        let mut payload_attestations = self
            .op_pool
            .get_payload_attestations(&state, parent_root, &self.spec)
            .map_err(BlockProductionError::OpPoolError)?;

        // If paranoid mode is enabled re-check the signatures of every included message.
        // This will be a lot slower but guards against bugs in block production and can be
        // quickly rolled out without a release.
        if self.config.paranoid_block_proposal {
            let mut tmp_ctxt = ConsensusContext::new(state.slot());
            attestations.retain(|att| {
                verify_attestation_for_block_inclusion(
                    &state,
                    att.to_ref(),
                    &mut tmp_ctxt,
                    VerifySignatures::True,
                    &self.spec,
                )
                .map_err(|e| {
                    warn!(
                        err = ?e,
                        block_slot = %state.slot(),
                        attestation = ?att,
                        "Attempted to include an invalid attestation"
                    );
                })
                .is_ok()
            });

            payload_attestations.retain(|att| {
                match get_indexed_payload_attestation(&state, att, &self.spec) {
                    Ok(indexed) => is_valid_indexed_payload_attestation(
                        &state,
                        &indexed,
                        VerifySignatures::True,
                        &self.spec,
                    )
                    .map_err(|e| {
                        warn!(
                            err = ?e,
                            block_slot = %state.slot(),
                            ?att,
                            "Attempted to include a payload attestation with invalid signature"
                        );
                    })
                    .is_ok(),
                    Err(e) => {
                        warn!(
                            err = ?e,
                            block_slot = %state.slot(),
                            ?att,
                            "Failed to index payload attestation for verification"
                        );
                        false
                    }
                }
            });

            proposer_slashings.retain(|slashing| {
                slashing
                    .clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            err = ?e,
                            block_slot = %state.slot(),
                            ?slashing,
                            "Attempted to include an invalid proposer slashing"
                        );
                    })
                    .is_ok()
            });

            attester_slashings.retain(|slashing| {
                slashing
                    .clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            err = ?e,
                            block_slot = %state.slot(),
                            ?slashing,
                            "Attempted to include an invalid attester slashing"
                        );
                    })
                    .is_ok()
            });

            voluntary_exits.retain(|exit| {
                exit.clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            err = ?e,
                            block_slot = %state.slot(),
                            ?exit,
                            "Attempted to include an invalid voluntary exit"
                        );
                    })
                    .is_ok()
            });
        }

        let attester_slashings = attester_slashings
            .into_iter()
            .filter_map(|a| match a {
                AttesterSlashing::Base(_) => None,
                AttesterSlashing::Electra(a) => Some(a),
            })
            .collect::<Vec<_>>();

        let attestations = attestations
            .into_iter()
            .filter_map(|a| match a {
                Attestation::Base(_) => None,
                Attestation::Electra(a) => Some(a),
            })
            .collect::<Vec<_>>();

        let slot = state.slot();

        let sync_aggregate = self
            .op_pool
            .get_sync_aggregate(&state)
            .map_err(BlockProductionError::OpPoolError)?
            .unwrap_or_else(|| {
                warn!(
                    slot = %state.slot(),
                    "Producing block with no sync contributions"
                );
                SyncAggregate::new()
            });

        Ok((
            PartialBeaconBlock {
                slot,
                proposer_index,
                parent_root,
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings,
                attester_slashings,
                attestations,
                deposits,
                voluntary_exits,
                sync_aggregate,
                payload_attestations,
                bls_to_execution_changes,
            },
            state,
        ))
    }

    /// Complete a block by computing its state root, and
    ///
    /// Return `(block, post_block_state, block_value)` where:
    ///
    /// - `post_block_state` is the state post block application
    /// - `block_value` is the consensus-layer rewards for `block`
    #[allow(clippy::type_complexity)]
    #[instrument(skip_all, level = "debug")]
    fn complete_partial_beacon_block_gloas(
        &self,
        partial_beacon_block: PartialBeaconBlock<T::EthSpec>,
        signed_execution_payload_bid: SignedExecutionPayloadBid<T::EthSpec>,
        parent_execution_requests: ExecutionRequests<T::EthSpec>,
        payload_data: Option<ExecutionPayloadData<T::EthSpec>>,
        mut state: BeaconState<T::EthSpec>,
        verification: ProduceBlockVerification,
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        let PartialBeaconBlock {
            slot,
            proposer_index,
            parent_root,
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            payload_attestations,
            bls_to_execution_changes,
        } = partial_beacon_block;

        let beacon_block = match &state {
            BeaconState::Base(_)
            | BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_)
            | BeaconState::Fulu(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Gloas(_) => BeaconBlock::Gloas(BeaconBlockGloas {
                slot,
                proposer_index,
                parent_root,
                state_root: Hash256::ZERO,
                body: BeaconBlockBodyGloas {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    attester_slashings: attester_slashings
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    attestations: attestations
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    deposits: deposits
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    voluntary_exits: voluntary_exits
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    sync_aggregate,
                    bls_to_execution_changes: bls_to_execution_changes
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    parent_execution_requests,
                    signed_execution_payload_bid,
                    payload_attestations: payload_attestations
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
                    _phantom: PhantomData::<FullPayload<T::EthSpec>>,
                },
            }),
        };

        let signed_beacon_block = SignedBeaconBlock::from_block(
            beacon_block,
            // The block is not signed here, that is the task of a validator client.
            Signature::empty(),
        );

        let block_size = signed_beacon_block.ssz_bytes_len();
        debug!(%block_size, "Produced block on state");

        metrics::observe(&metrics::BLOCK_SIZE, block_size as f64);

        if block_size > self.config.max_network_size {
            return Err(BlockProductionError::BlockTooLarge(block_size));
        }

        let process_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_PROCESS_TIMES);
        let signature_strategy = match verification {
            ProduceBlockVerification::VerifyRandao => BlockSignatureStrategy::VerifyRandao,
            ProduceBlockVerification::NoVerification => BlockSignatureStrategy::NoVerification,
        };

        // Use a context without block root or proposer index so that both are checked.
        let mut ctxt = ConsensusContext::new(signed_beacon_block.slot());

        let consensus_block_value = self
            .compute_beacon_block_reward(signed_beacon_block.message(), &mut state)
            .map(|reward| reward.total)
            .unwrap_or(0);

        state_processing::per_block_processing(
            &mut state,
            &signed_beacon_block,
            signature_strategy,
            VerifyBlockRoot::True,
            &mut ctxt,
            &self.spec,
        )?;
        drop(process_timer);

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_ROOT_TIMES);

        let state_root = state.update_tree_hash_cache()?;

        drop(state_root_timer);

        let (mut block, _) = signed_beacon_block.deconstruct();
        *block.state_root_mut() = state_root;

        // Construct and cache the ExecutionPayloadEnvelope if we have payload data.
        // For local building, we always have payload data.
        // For trustless building, the builder will provide the envelope separately.
        if let Some(payload_data) = payload_data {
            let beacon_block_root = block.tree_hash_root();
            let parent_beacon_block_root = block.parent_root();
            let execution_payload_envelope = ExecutionPayloadEnvelope {
                payload: payload_data.payload,
                execution_requests: payload_data.execution_requests,
                builder_index: payload_data.builder_index,
                beacon_block_root,
                parent_beacon_block_root,
            };

            let signed_envelope = SignedExecutionPayloadEnvelope {
                message: execution_payload_envelope,
                signature: Signature::empty(),
            };

            // Verify the envelope against the state. This performs no state mutation.
            verify_execution_payload_envelope(
                &state,
                &signed_envelope,
                VerifySignatures::False,
                state_root,
                &self.spec,
            )
            .map_err(BlockProductionError::EnvelopeProcessingError)?;

            // Cache the envelope for later retrieval by the validator for signing and publishing.
            let envelope_slot = payload_data.slot;
            // TODO(gloas) might be safer to cache by root instead of by slot.
            // We should revisit this once this code path + beacon api spec matures
            let (blobs, _) = payload_data.blobs_and_proofs;
            self.pending_payload_envelopes.write().insert(
                envelope_slot,
                PendingEnvelopeData {
                    envelope: signed_envelope.message,
                    blobs: Some(blobs),
                },
            );

            debug!(
                %beacon_block_root,
                slot = %envelope_slot,
                "Cached pending execution payload envelope"
            );
        }

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);

        trace!(
            parent = ?block.parent_root(),
            attestations = block.body().attestations_len(),
            slot = %block.slot(),
            "Produced beacon block"
        );

        Ok((block, state, consensus_block_value))
    }

    /// Produce a self-build `ExecutionPayloadBid` for some `slot` upon the given `state`.
    /// This function assumes we've already advanced `state`.
    ///
    /// Returns the signed bid, the state, and a `LocalBuildResult` carrying the payload
    /// data needed to construct the `ExecutionPayloadEnvelope` after the beacon block is
    /// created, plus the EL block value and `should_override_builder` flag used by the
    /// caller to compare against any cached p2p builder bid.
    #[allow(clippy::type_complexity)]
    #[instrument(level = "debug", skip_all)]
    pub async fn produce_execution_payload_bid(
        self: Arc<Self>,
        state: BeaconState<T::EthSpec>,
        parent_payload_status: PayloadStatus,
        parent_envelope: Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>,
        produce_at_slot: Slot,
        bid_value: u64,
        builder_index: BuilderIndex,
    ) -> Result<
        (
            SignedExecutionPayloadBid<T::EthSpec>,
            BeaconState<T::EthSpec>,
            LocalBuildResult<T::EthSpec>,
        ),
        BlockProductionError,
    > {
        // TODO(gloas) For non local building, add sanity check on value
        // The builder MUST have enough excess balance to fulfill this bid (i.e. `value`) and all pending payments.

        // TODO(gloas) add metrics for execution payload bid production

        let parent_root = if state.slot() > 0 {
            *state
                .get_block_root(state.slot() - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header().canonical_root()
        };

        let proposer_index = state.get_beacon_proposer_index(state.slot(), &self.spec)? as u64;

        let pubkey = state
            .validators()
            .get(proposer_index as usize)
            .map(|v| v.pubkey)
            .ok_or(BlockProductionError::BeaconChain(Box::new(
                BeaconChainError::ValidatorIndexUnknown(proposer_index as usize),
            )))?;

        let builder_params = BuilderParams {
            pubkey,
            slot: state.slot(),
            chain_health: self
                .is_healthy(&parent_root)
                .map_err(|e| BlockProductionError::BeaconChain(Box::new(e)))?,
        };

        let parent_bid = state.latest_execution_payload_bid()?;

        // TODO(gloas): need should_extend_payload check here as well
        let parent_block_slot = state.latest_block_header().slot;
        let parent_is_pre_gloas = !self
            .spec
            .fork_name_at_slot::<T::EthSpec>(parent_block_slot)
            .gloas_enabled();
        let parent_block_hash =
            if parent_payload_status == PayloadStatus::Full || parent_is_pre_gloas {
                // Build on parent bid's payload.
                parent_bid.block_hash
            } else {
                // Skip parent bid's payload. For genesis this is the EL genesis hash.
                parent_bid.parent_block_hash
            };

        // TODO(gloas) this should be BlockProductionVersion::V4
        // V3 is okay for now as long as we're not connected to a builder
        // TODO(gloas) add builder boost factor
        let prepare_payload_handle = get_execution_payload_gloas(
            self.clone(),
            &state,
            parent_root,
            parent_block_hash,
            parent_envelope,
            proposer_index,
            builder_params,
        )?;

        let block_proposal_contents = prepare_payload_handle
            .await
            .map_err(BlockProductionError::TokioJoin)?
            .ok_or(BlockProductionError::ShuttingDown)??;

        let BlockProposalContentsGloas {
            payload,
            payload_value,
            execution_requests,
            blob_kzg_commitments,
            blobs_and_proofs,
            should_override_builder,
        } = block_proposal_contents;

        // TODO(gloas) since we are defaulting to local building, execution payment is 0
        // execution payment should only be set to > 0 for trusted building.
        let bid = ExecutionPayloadBid::<T::EthSpec> {
            parent_block_hash,
            parent_block_root: parent_root,
            block_hash: payload.block_hash,
            prev_randao: payload.prev_randao,
            fee_recipient: Address::ZERO,
            gas_limit: payload.gas_limit,
            builder_index,
            slot: produce_at_slot,
            value: bid_value,
            execution_payment: EXECUTION_PAYMENT_TRUSTLESS_BUILD,
            blob_kzg_commitments,
            execution_requests_root: execution_requests.tree_hash_root(),
        };

        // Store payload data for envelope construction after block is created
        let payload_data = ExecutionPayloadData {
            payload,
            execution_requests,
            builder_index,
            slot: produce_at_slot,
            blobs_and_proofs,
        };

        Ok((
            SignedExecutionPayloadBid {
                message: bid,
                signature: Signature::infinity().map_err(BlockProductionError::BlsError)?,
            },
            state,
            LocalBuildResult {
                payload_data,
                payload_value,
                should_override_builder,
            },
        ))
    }

    /// Look up the highest gossip-verified bid for the `(slot, parent_block_hash,
    /// parent_block_root)` of the local bid, then choose the winner.
    fn select_payload_bid(
        &self,
        local_signed_bid: SignedExecutionPayloadBid<T::EthSpec>,
        local_build: LocalBuildResult<T::EthSpec>,
        builder_boost_factor: Option<u64>,
    ) -> (
        SignedExecutionPayloadBid<T::EthSpec>,
        Option<ExecutionPayloadData<T::EthSpec>>,
    ) {
        let cached_bid = self.gossip_verified_payload_bid_cache.get_highest_bid(
            local_signed_bid.message.slot,
            local_signed_bid.message.parent_block_hash,
            local_signed_bid.message.parent_block_root,
        );
        select_payload_bid_pure(
            local_signed_bid,
            local_build,
            cached_bid,
            builder_boost_factor,
        )
    }
}

/// Pure local-vs-cached selection logic, factored out for unit testing.
///
/// Selection rule (mirrors the pre-Gloas builder/local race in `execution_layer`):
///   - `boosted_bid = (cached_bid.value / 100) * builder_boost_factor`  (raw value when `None`)
///   - if `local_value_wei >= boosted_bid_wei` → keep local
///   - if the EL signaled `should_override_builder` → keep local
///   - otherwise → use the cached builder bid and drop local payload data
///     (the builder is responsible for revealing the envelope).
///
/// `cached_bid.value` is in gwei (`u64`); `payload_value` is in wei (`Uint256`); compared in wei.
pub(crate) fn select_payload_bid_pure<E: EthSpec>(
    local_signed_bid: SignedExecutionPayloadBid<E>,
    local_build: LocalBuildResult<E>,
    cached_bid: Option<Arc<SignedExecutionPayloadBid<E>>>,
    builder_boost_factor: Option<u64>,
) -> (
    SignedExecutionPayloadBid<E>,
    Option<ExecutionPayloadData<E>>,
) {
    let LocalBuildResult {
        payload_data,
        payload_value,
        should_override_builder,
    } = local_build;

    let Some(cached_bid) = cached_bid else {
        return (local_signed_bid, Some(payload_data));
    };

    let slot = local_signed_bid.message.slot;

    if should_override_builder {
        debug!(
            %slot,
            cached_bid_value = cached_bid.message.value,
            "Using local payload because EL signaled shouldOverrideBuilder"
        );
        return (local_signed_bid, Some(payload_data));
    }

    // Convert bid value (gwei) to wei for comparison with `payload_value` (wei).
    let bid_value_wei = types::Uint256::from(cached_bid.message.value)
        .saturating_mul(types::Uint256::from(1_000_000_000u64));
    let boosted_bid_wei = match builder_boost_factor {
        Some(factor) => {
            (bid_value_wei / types::Uint256::from(100)).saturating_mul(types::Uint256::from(factor))
        }
        None => bid_value_wei,
    };

    if payload_value >= boosted_bid_wei {
        debug!(
            %slot,
            %payload_value,
            cached_bid_value_gwei = cached_bid.message.value,
            ?builder_boost_factor,
            "Local payload is more profitable than cached builder bid"
        );
        (local_signed_bid, Some(payload_data))
    } else {
        debug!(
            %slot,
            %payload_value,
            cached_bid_value_gwei = cached_bid.message.value,
            cached_bid_builder_index = cached_bid.message.builder_index,
            ?builder_boost_factor,
            "Including cached builder bid"
        );
        ((*cached_bid).clone(), None)
    }
}

/// Gets an execution payload for inclusion in a block.
///
/// ## Errors
///
/// Will return an error when using a pre-Gloas `state`. Ensure to only run this function
/// after the Gloas fork.
fn get_execution_payload_gloas<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    state: &BeaconState<T::EthSpec>,
    parent_beacon_block_root: Hash256,
    parent_block_hash: ExecutionBlockHash,
    parent_envelope: Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>,
    proposer_index: u64,
    builder_params: BuilderParams,
) -> Result<PreparePayloadHandle<T::EthSpec>, BlockProductionError> {
    // Compute all required values from the `state` now to avoid needing to pass it into a spawned
    // task.
    let spec = &chain.spec;
    let current_epoch = state.current_epoch();
    let timestamp =
        compute_timestamp_at_slot(state, state.slot(), spec).map_err(BeaconStateError::from)?;
    let random = *state.get_randao_mix(current_epoch)?;

    // TODO(gloas): this gas limit calc is not necessarily right
    let parent_bid = state.latest_execution_payload_bid()?;
    let latest_gas_limit = parent_bid.gas_limit;

    let is_parent_block_full = parent_block_hash == parent_bid.block_hash;

    let withdrawals = if is_parent_block_full {
        if let Some(envelope) = parent_envelope {
            let mut withdrawals_state = state.clone();
            apply_parent_execution_payload(
                &mut withdrawals_state,
                &envelope.message.execution_requests,
                spec,
            )?;
            Withdrawals::<T::EthSpec>::from(get_expected_withdrawals(&withdrawals_state, spec)?)
                .into()
        } else {
            // No envelope available (e.g. genesis). The parent had no execution requests,
            // so compute withdrawals directly from the current state.
            Withdrawals::<T::EthSpec>::from(get_expected_withdrawals(state, spec)?).into()
        }
    } else {
        // If the previous payload was missed, carry forward the withdrawals from the state.
        state.payload_expected_withdrawals()?.to_vec()
    };

    // Spawn a task to obtain the execution payload from the EL via a series of async calls. The
    // `join_handle` can be used to await the result of the function.
    let join_handle = chain
        .task_executor
        .clone()
        .spawn_handle(
            async move {
                prepare_execution_payload::<T>(
                    &chain,
                    timestamp,
                    random,
                    proposer_index,
                    parent_block_hash,
                    latest_gas_limit,
                    builder_params,
                    withdrawals,
                    parent_beacon_block_root,
                )
                .await
            }
            .instrument(debug_span!("prepare_execution_payload")),
            "prepare_execution_payload",
        )
        .ok_or(BlockProductionError::ShuttingDown)?;

    Ok(join_handle)
}

/// Prepares an execution payload for inclusion in a block.
///
/// ## Errors
///
/// Will return an error when using a pre-Gloas fork `state`. Ensure to only run this function
/// after the Gloas fork.
#[allow(clippy::too_many_arguments)]
async fn prepare_execution_payload<T>(
    chain: &Arc<BeaconChain<T>>,
    timestamp: u64,
    random: Hash256,
    proposer_index: u64,
    parent_block_hash: ExecutionBlockHash,
    parent_gas_limit: u64,
    builder_params: BuilderParams,
    withdrawals: Vec<Withdrawal>,
    parent_beacon_block_root: Hash256,
) -> Result<BlockProposalContentsGloas<T::EthSpec>, BlockProductionError>
where
    T: BeaconChainTypes,
{
    let spec = &chain.spec;
    let fork = spec.fork_name_at_slot::<T::EthSpec>(builder_params.slot);
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    // Try to obtain the fork choice update parameters from the cached head.
    //
    // Use a blocking task to interact with the `canonical_head` lock otherwise we risk blocking the
    // core `tokio` executor.
    let inner_chain = chain.clone();
    let forkchoice_update_params = chain
        .spawn_blocking_handle(
            move || {
                inner_chain
                    .canonical_head
                    .cached_head()
                    .forkchoice_update_parameters()
            },
            "prepare_execution_payload_forkchoice_update_params",
        )
        .instrument(debug_span!("forkchoice_update_params"))
        .await
        .map_err(|e| BlockProductionError::BeaconChain(Box::new(e)))?;

    let suggested_fee_recipient = execution_layer
        .get_suggested_fee_recipient(proposer_index)
        .await;
    let slot_number = Some(builder_params.slot.as_u64());

    let payload_attributes = PayloadAttributes::new(
        timestamp,
        random,
        suggested_fee_recipient,
        Some(withdrawals),
        Some(parent_beacon_block_root),
        slot_number,
    );

    let target_gas_limit = execution_layer.get_proposer_gas_limit(proposer_index).await;
    let payload_parameters = PayloadParameters {
        parent_hash: parent_block_hash,
        parent_gas_limit,
        proposer_gas_limit: target_gas_limit,
        payload_attributes: &payload_attributes,
        forkchoice_update_params: &forkchoice_update_params,
        current_fork: fork,
    };

    let block_contents = execution_layer
        .get_payload_gloas(payload_parameters)
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    Ok(block_contents)
}

/// Drop voluntary exits whose target validators will be exited by the parent envelope's
/// execution requests.
///
/// In Gloas the parent execution payload is processed before voluntary exits during block
/// processing. EL-triggered withdrawal-full-exit requests (EIP-7002) and cross-pubkey
/// consolidation requests (EIP-7251) call `initiate_validator_exit`, setting the target's
/// `exit_epoch`. A voluntary exit for the same validator would then fail with `AlreadyExited`.
fn filter_voluntary_exits_for_parent_execution_requests<E: EthSpec>(
    voluntary_exits: &mut Vec<SignedVoluntaryExit>,
    parent_execution_requests: &ExecutionRequests<E>,
    pubkey_at_index: impl Fn(u64) -> Option<PublicKeyBytes>,
    spec: &ChainSpec,
) {
    let mut exited_pubkeys = HashSet::with_capacity(
        parent_execution_requests.withdrawals.len()
            + parent_execution_requests.consolidations.len(),
    );
    for req in &parent_execution_requests.withdrawals {
        if req.amount == spec.full_exit_request_amount {
            exited_pubkeys.insert(req.validator_pubkey);
        }
    }
    for req in &parent_execution_requests.consolidations {
        if req.source_pubkey != req.target_pubkey {
            exited_pubkeys.insert(req.source_pubkey);
        }
    }
    if !exited_pubkeys.is_empty() {
        voluntary_exits.retain(|exit| {
            pubkey_at_index(exit.message.validator_index)
                .map(|pk| !exited_pubkeys.contains(&pk))
                .unwrap_or(false)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::VariableList;
    use types::{ConsolidationRequest, Epoch, MainnetEthSpec, VoluntaryExit, WithdrawalRequest};

    type TestSpec = MainnetEthSpec;

    fn pubkey(byte: u8) -> PublicKeyBytes {
        PublicKeyBytes::deserialize(&[byte; 48]).expect("valid pubkey byte length")
    }

    fn exit(validator_index: u64) -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: Epoch::new(0),
                validator_index,
            },
            signature: Signature::empty(),
        }
    }

    fn requests(
        withdrawals: Vec<WithdrawalRequest>,
        consolidations: Vec<ConsolidationRequest>,
    ) -> ExecutionRequests<TestSpec> {
        ExecutionRequests {
            deposits: VariableList::empty(),
            withdrawals: VariableList::new(withdrawals).unwrap(),
            consolidations: VariableList::new(consolidations).unwrap(),
        }
    }

    fn run_filter(
        exits: &mut Vec<SignedVoluntaryExit>,
        requests: &ExecutionRequests<TestSpec>,
        validator_pubkeys: &[PublicKeyBytes],
        spec: &ChainSpec,
    ) {
        filter_voluntary_exits_for_parent_execution_requests(
            exits,
            requests,
            |idx| validator_pubkeys.get(idx as usize).copied(),
            spec,
        );
    }

    #[test]
    fn full_exit_withdrawal_request_filters_matching_voluntary_exit() {
        let spec = ChainSpec::mainnet();
        let validators = vec![pubkey(1), pubkey(2)];
        let mut exits = vec![exit(0), exit(1)];
        let reqs = requests(
            vec![WithdrawalRequest {
                source_address: Address::repeat_byte(0xaa),
                validator_pubkey: validators[0],
                amount: spec.full_exit_request_amount,
            }],
            vec![],
        );

        run_filter(&mut exits, &reqs, &validators, &spec);

        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].message.validator_index, 1);
    }

    #[test]
    fn partial_withdrawal_request_does_not_filter_voluntary_exit() {
        let spec = ChainSpec::mainnet();
        let validators = vec![pubkey(1)];
        let mut exits = vec![exit(0)];
        let reqs = requests(
            vec![WithdrawalRequest {
                source_address: Address::repeat_byte(0xaa),
                validator_pubkey: validators[0],
                amount: spec.full_exit_request_amount + 1,
            }],
            vec![],
        );

        run_filter(&mut exits, &reqs, &validators, &spec);

        assert_eq!(exits.len(), 1);
    }

    #[test]
    fn cross_pubkey_consolidation_filters_voluntary_exit_for_source_only() {
        let spec = ChainSpec::mainnet();
        let validators = vec![pubkey(1), pubkey(2), pubkey(3)];
        let mut exits = vec![exit(0), exit(1), exit(2)];
        let reqs = requests(
            vec![],
            vec![ConsolidationRequest {
                source_address: Address::repeat_byte(0xaa),
                source_pubkey: validators[1],
                target_pubkey: validators[2],
            }],
        );

        run_filter(&mut exits, &reqs, &validators, &spec);

        // The source (validator 1) is exited; the target (validator 2) is not.
        let remaining: Vec<u64> = exits.iter().map(|e| e.message.validator_index).collect();
        assert_eq!(remaining, vec![0, 2]);
    }

    #[test]
    fn self_consolidation_does_not_filter_voluntary_exit() {
        let spec = ChainSpec::mainnet();
        let validators = vec![pubkey(1)];
        let mut exits = vec![exit(0)];
        let reqs = requests(
            vec![],
            vec![ConsolidationRequest {
                source_address: Address::repeat_byte(0xaa),
                source_pubkey: validators[0],
                target_pubkey: validators[0],
            }],
        );

        run_filter(&mut exits, &reqs, &validators, &spec);

        assert_eq!(exits.len(), 1);
    }

    #[test]
    fn empty_parent_requests_preserve_voluntary_exits() {
        let spec = ChainSpec::mainnet();
        let validators = vec![pubkey(1), pubkey(2)];
        let mut exits = vec![exit(0), exit(1)];
        let reqs = requests(vec![], vec![]);

        run_filter(&mut exits, &reqs, &validators, &spec);

        assert_eq!(exits.len(), 2);
    }

    // ---- select_payload_bid_pure ----

    const REMOTE_BUILDER: BuilderIndex = 999;

    fn gwei(n: u64) -> types::Uint256 {
        types::Uint256::from(n).saturating_mul(types::Uint256::from(1_000_000_000u64))
    }

    fn local_bid() -> SignedExecutionPayloadBid<TestSpec> {
        SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                builder_index: BUILDER_INDEX_SELF_BUILD,
                ..Default::default()
            },
            signature: Signature::empty(),
        }
    }

    fn cached_bid(value_gwei: u64) -> Arc<SignedExecutionPayloadBid<TestSpec>> {
        Arc::new(SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                builder_index: REMOTE_BUILDER,
                value: value_gwei,
                ..Default::default()
            },
            signature: Signature::empty(),
        })
    }

    fn local_build(payload_gwei: u64, should_override_builder: bool) -> LocalBuildResult<TestSpec> {
        LocalBuildResult {
            payload_data: ExecutionPayloadData {
                payload: types::ExecutionPayloadGloas::default(),
                execution_requests: ExecutionRequests::default(),
                builder_index: BUILDER_INDEX_SELF_BUILD,
                slot: Slot::new(0),
                blobs_and_proofs: (VariableList::empty(), VariableList::empty()),
            },
            payload_value: gwei(payload_gwei),
            should_override_builder,
        }
    }

    const LOCAL: BuilderIndex = BUILDER_INDEX_SELF_BUILD;
    const REMOTE: BuilderIndex = REMOTE_BUILDER;

    /// Run `select_payload_bid_pure` and return `(winning_builder_index, has_payload_data)`.
    ///
    /// Args (positional, mirror `select_payload_bid_pure`):
    ///   - `local_payload_gwei`: local payload value, in gwei.
    ///   - `should_override`:    EL's `shouldOverrideBuilder` flag.
    ///   - `cached_gwei`:        `Some(g)` ⇒ seed the cache with a bid of `g` gwei.
    ///   - `boost`:              `None` = neutral, `Some(0)` = always local, `Some(>100)` = boost bid.
    fn pick(
        local_payload_gwei: u64,
        should_override: bool,
        cached_gwei: Option<u64>,
        boost: Option<u64>,
    ) -> (BuilderIndex, bool) {
        let build = local_build(local_payload_gwei, should_override);
        let cache = cached_gwei.map(cached_bid);
        let (out, data) = select_payload_bid_pure::<TestSpec>(local_bid(), build, cache, boost);
        (out.message.builder_index, data.is_some())
    }

    #[test]
    fn select_empty_cache_keeps_local() {
        assert_eq!(pick(0, false, None, Some(u64::MAX)), (LOCAL, true));
    }

    #[test]
    fn select_el_override_beats_any_cached_bid() {
        // `shouldOverrideBuilder` short-circuits regardless of cache or boost.
        assert_eq!(pick(0, true, Some(u64::MAX), Some(u64::MAX)), (LOCAL, true));
    }

    #[test]
    fn select_boost_zero_always_keeps_local() {
        // boost=0 deflates the bid to 0 ⇒ local always wins.
        assert_eq!(pick(0, false, Some(u64::MAX), Some(0)), (LOCAL, true));
    }

    #[test]
    fn select_neutral_boost_picks_higher_bid() {
        // 5 gwei bid > 1 gwei local, neutral compare ⇒ bid.
        assert_eq!(pick(1, false, Some(5), None), (REMOTE, false));
    }

    #[test]
    fn select_local_strictly_higher_keeps_local() {
        assert_eq!(pick(10, false, Some(5), None), (LOCAL, true));
    }

    #[test]
    fn select_tie_goes_to_local() {
        // `>=` ⇒ local wins ties.
        assert_eq!(pick(5, false, Some(5), None), (LOCAL, true));
    }

    #[test]
    fn select_boost_factor_amplifies_bid() {
        // 5 gwei local vs 3 gwei bid: raw ⇒ local.
        assert_eq!(pick(5, false, Some(3), None), (LOCAL, true));
        // boost=200 ⇒ bid scaled to 6 gwei ⇒ bid wins.
        assert_eq!(pick(5, false, Some(3), Some(200)), (REMOTE, false));
    }
}

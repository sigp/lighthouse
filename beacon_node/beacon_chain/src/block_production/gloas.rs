use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use bls::Signature;
use execution_layer::{
    BlockProposalContentsGloas, BuilderParams, PayloadAttributes, PayloadParameters,
};
use fork_choice::PayloadStatus;
use operation_pool::CompactAttestationRef;
use ssz::Encode;
use state_processing::common::get_attesting_indices_from_state;
use state_processing::envelope_processing::verify_execution_payload_envelope;
use state_processing::epoch_cache::initialize_epoch_cache;
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
    BuilderIndex, Deposit, Eth1Data, EthSpec, ExecutionBlockHash, ExecutionPayloadBid,
    ExecutionPayloadEnvelope, ExecutionPayloadGloas, ExecutionRequests, FullPayload, Graffiti,
    Hash256, PayloadAttestation, ProposerSlashing, RelativeEpoch, SignedBeaconBlock,
    SignedBlsToExecutionChange, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    SignedVoluntaryExit, Slot, SyncAggregate, Withdrawal, Withdrawals,
};

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
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn produce_block_with_verification_gloas(
        self: &Arc<Self>,
        randao_reveal: Signature,
        slot: Slot,
        graffiti_settings: GraffitiSettings,
        verification: ProduceBlockVerification,
        _builder_boost_factor: Option<u64>,
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
        )
        .await
    }

    // TODO(gloas) need to implement builder boost factor logic
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
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        // Part 1/3 (blocking)
        //
        // Perform the state advance and block-packing functions.
        let chain = self.clone();
        let graffiti = self
            .graffiti_calculator
            .get_graffiti(graffiti_settings)
            .await;
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
                    )
                },
                "produce_partial_beacon_block_gloas",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        // Extract the parent's execution requests from the envelope (if parent was full).
        let parent_execution_requests = if parent_payload_status == PayloadStatus::Full {
            parent_envelope
                .as_ref()
                .map(|env| env.message.execution_requests.clone())
                .ok_or(BlockProductionError::MissingParentExecutionPayload)?
        } else {
            ExecutionRequests::default()
        };

        // Part 2/3 (async)
        //
        // Produce the execution payload bid.
        // TODO(gloas) this is strictly for building local bids
        // We'll need to build out trustless/trusted bid paths.
        let (execution_payload_bid, state, payload_data) = self
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

            // TODO(gloas) verify payload attestation signature here as well
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
                // TODO(gloas) need to implement payload attestations
                payload_attestations: vec![],
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
            let execution_payload_envelope = ExecutionPayloadEnvelope {
                payload: payload_data.payload,
                execution_requests: payload_data.execution_requests,
                builder_index: payload_data.builder_index,
                beacon_block_root,
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
            self.pending_payload_envelopes
                .write()
                .insert(envelope_slot, signed_envelope.message);

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

    // TODO(gloas) introduce `ProposerPreferences` so we can build out trustless
    // bid building. Right now this only works for local building.
    /// Produce an `ExecutionPayloadBid` for some `slot` upon the given `state`.
    /// This function assumes we've already advanced `state`.
    ///
    /// Returns the signed bid, the state, and optionally the payload data needed to construct
    /// the `ExecutionPayloadEnvelope` after the beacon block is created.
    ///
    /// For local building, payload data is always returned (`Some`).
    /// For trustless building, the builder provides the envelope separately, so `None` is returned.
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
            Option<ExecutionPayloadData<T::EthSpec>>,
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
        let parent_block_hash = if parent_payload_status == PayloadStatus::Full {
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
            payload_value: _,
            execution_requests,
            blob_kzg_commitments,
            blobs_and_proofs: _,
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
        };

        // TODO(gloas) this is only local building
        // we'll need to implement builder signature for the trustless path
        Ok((
            SignedExecutionPayloadBid {
                message: bid,
                signature: Signature::infinity().map_err(BlockProductionError::BlsError)?,
            },
            state,
            // Local building always returns payload data.
            // Trustless building would return None here.
            Some(payload_data),
        ))
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
                parent_bid,
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

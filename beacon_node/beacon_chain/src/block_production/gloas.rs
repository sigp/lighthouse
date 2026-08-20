use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;

use proto_array::PayloadStatus;

use bls::{PublicKeyBytes, Signature};
use execution_layer::{
    BlockProposalContentsGloas, BuilderParams, DEFAULT_GAS_LIMIT, PayloadAttributes,
    PayloadParameters,
};
use operation_pool::CompactAttestationRef;
use ssz::{Encode, ProgressiveBitList};
use ssz_types::ProgressiveVariableList;
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
    Address, Attestation, AttestationGloas, AttesterSlashing, AttesterSlashingGloas, BeaconBlock,
    BeaconBlockBodyGloas, BeaconBlockGloas, BeaconState, BeaconStateError, BlobsList, BuilderIndex,
    ChainSpec, Deposit, Eth1Data, EthSpec, ExecutionBlockHash, ExecutionPayloadBid,
    ExecutionPayloadEnvelope, ExecutionRequestsGloas, FullPayload, Graffiti, Hash256,
    IndexedAttestation, KzgProofs, PayloadAttestation, ProposerSlashing, RelativeEpoch,
    SignedBeaconBlock, SignedBlsToExecutionChange, SignedExecutionPayloadBid,
    SignedExecutionPayloadEnvelope, SignedProposerPreferences, SignedVoluntaryExit, Slot,
    SyncAggregate, Uint256, Withdrawal, Withdrawals,
};

use builder_client::BidRequestContext;
use eth2::types::BuilderConfig;
use sensitive_url::SensitiveUrl;

use crate::block_production::bid_selection::{self, BidCandidate, BidSource, ExecutionPayloadData};
use crate::payload_bid_verification::PayloadBidError;
use crate::payload_bid_verification::direct_verified_bid::verify_direct_bid;
use crate::payload_bid_verification::gossip_verified_bid::verify_bid_state_conditions;
use crate::payload_bid_verification::payload_bid_cache::BidParent;
use crate::pending_payload_envelopes::PendingEnvelopeData;
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError,
    ProduceBlockVerification, block_production::BlockProductionState,
    graffiti_calculator::GraffitiSettings, metrics,
};

pub const BID_VALUE_SELF_BUILD: u64 = 0;
pub const EXECUTION_PAYMENT_TRUSTLESS_BUILD: u64 = 0;

type ConsensusBlockValue = u64;

pub type PayloadEnvelopeContents<E> = (
    Arc<ExecutionPayloadEnvelope<E>>,
    KzgProofs<E>,
    Arc<BlobsList<E>>,
);

/// Execution payload value in wei: the local payload's EL value when self-building, or the
/// bid value when committing to a builder bid.
type ExecutionPayloadValue = Uint256;

type BlockProductionResult<E> = (
    BeaconBlock<E>,
    BeaconState<E>,
    ConsensusBlockValue,
    ExecutionPayloadValue,
    Option<PayloadEnvelopeContents<E>>,
    // The winning builder's URL when a direct builder won, for the `Eth-Builder-Url` response header.
    // Kept as a `SensitiveUrl` (redacted in logs); stringified only at the header boundary.
    Option<SensitiveUrl>,
);

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
    attester_slashings: Vec<AttesterSlashingGloas<E>>,
    attestations: Vec<AttestationGloas<E>>,
    payload_attestations: Vec<PayloadAttestation<E>>,
    deposits: Vec<Deposit>,
    voluntary_exits: Vec<SignedVoluntaryExit>,
    sync_aggregate: SyncAggregate<E>,
    bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
}

/// The result of a local payload build, used to decide whether to include a builder bid
/// from the gossip cache or fall back to self-build.
///
/// [`ExecutionPayloadData`] and the selection types ([`BidCandidate`], [`BidSource`]) live in the
/// fork-agnostic [`bid_selection`](super::bid_selection) module.
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
        builder_config: BuilderConfig,
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
            builder_config,
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
        builder_config: BuilderConfig,
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        debug!(
            slot = %produce_at_slot,
            direct_builders = builder_config.builders.len(),
            "Producing Gloas block"
        );

        let parent_root = if state.slot() > 0 {
            *state
                .get_block_root(state.slot() - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header().canonical_root()
        };

        let should_build_on_full = self
            .canonical_head
            .fork_choice_read_lock()
            .should_build_on_full(&parent_root, parent_payload_status, produce_at_slot)
            .map_err(|e| {
                BlockProductionError::BeaconChain(Box::new(BeaconChainError::ForkChoiceError(e)))
            })?;

        // Extract the parent's execution requests from the envelope (if building on full).
        let parent_execution_requests = if should_build_on_full {
            parent_envelope
                .as_ref()
                .map(|env| env.message.execution_requests.clone())
                .ok_or(BlockProductionError::MissingParentExecutionPayload)?
        } else {
            ExecutionRequestsGloas::default()
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
        // Resolve the FULL/EMPTY parent execution hash, acquire the external candidates (direct
        // builder bids + the highest gossip bid), produce the local execution payload bid, and
        // select the most profitable eligible payload bid.

        // The FULL/EMPTY parent execution hash the payload builds on.
        let parent_bid = state.latest_execution_payload_bid()?;
        let parent_is_pre_gloas = !self
            .spec
            .fork_name_at_slot::<T::EthSpec>(state.latest_block_header().slot)
            .gloas_enabled();
        let parent_block_hash = if should_build_on_full || parent_is_pre_gloas {
            parent_bid.block_hash
        } else {
            parent_bid.parent_block_hash
        };

        // The per-proposal context addressing each `getExecutionPayloadBid`.
        let proposer_pubkey = state
            .get_validator(partial_beacon_block.proposer_index as usize)?
            .pubkey;
        let ctx = BidRequestContext {
            slot: produce_at_slot,
            parent_hash: parent_block_hash,
            parent_root,
            proposer_pubkey,
            fork_name: self.spec.fork_name_at_slot::<T::EthSpec>(produce_at_slot),
        };

        // The proposer's gossip-verified preferences for this slot, needed to validate direct bids.
        // Absent (the proposer never submitted any) => direct bids are skipped.
        let proposal_epoch = produce_at_slot.epoch(T::EthSpec::slots_per_epoch());
        let dependent_root = state.proposer_shuffling_decision_root_at_epoch(
            proposal_epoch,
            parent_root,
            &self.spec,
        )?;
        let proposer_preferences = self
            .gossip_verified_proposer_preferences_cache
            .get_preferences(&produce_at_slot, dependent_root);

        // Fire the direct builder fan-out concurrently with the local EL payload build: both only
        // read `state`, so they race without contention. A local EL failure is not fatal — we fall
        // back to an external bid when one is available; only a total absence of viable bids fails
        // production.
        let acquire_fut = self.acquire_external_bid_candidates(
            ctx,
            &builder_config,
            proposer_preferences.as_deref(),
            &state,
        );
        let local_fut = self.clone().produce_execution_payload_bid(
            &state,
            parent_envelope,
            produce_at_slot,
            BID_VALUE_SELF_BUILD,
            BUILDER_INDEX_SELF_BUILD,
            parent_block_hash,
        );
        let (mut candidates, local_result) = tokio::join!(acquire_fut, local_fut);

        match local_result {
            Ok((local_signed_bid, local_build)) => {
                let LocalBuildResult {
                    payload_data,
                    payload_value,
                    should_override_builder,
                } = local_build;
                candidates.push(BidCandidate::local(
                    local_signed_bid,
                    payload_data,
                    payload_value,
                    should_override_builder,
                ));
            }
            Err(e) => {
                error!(
                    error = ?e,
                    slot = %produce_at_slot,
                    "Local execution payload build failed; falling back to an external bid"
                );
            }
        }

        let winning_bid = bid_selection::select_payload_bid(candidates)
            .ok_or(BlockProductionError::NoViablePayloadBid)?;

        // Part 3/3 (blocking)
        //
        // Complete the block with the execution payload bid.
        let chain = self.clone();
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    chain.complete_partial_beacon_block_gloas(
                        partial_beacon_block,
                        winning_bid,
                        parent_execution_requests,
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
        parent_execution_requests: &ExecutionRequestsGloas<T::EthSpec>,
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
            .map(|a| match a {
                // Convert pre-Gloas slashings into the Gloas type. The SSZ bytes are the same,
                // only the hash tree root differs.
                AttesterSlashing::Base(a) => AttesterSlashingGloas {
                    attestation_1: IndexedAttestation::Base(a.attestation_1).to_gloas(),
                    attestation_2: IndexedAttestation::Base(a.attestation_2).to_gloas(),
                },
                AttesterSlashing::Electra(a) => AttesterSlashingGloas {
                    attestation_1: IndexedAttestation::Electra(a.attestation_1).to_gloas(),
                    attestation_2: IndexedAttestation::Electra(a.attestation_2).to_gloas(),
                },
                AttesterSlashing::Gloas(a) => a,
            })
            .collect::<Vec<_>>();

        let attestations = attestations
            .into_iter()
            .filter_map(|a| match a {
                Attestation::Base(_) => None,
                // Convert Electra attestations left over from before the fork into the Gloas
                // type. The SSZ bytes are the same, only the hash tree root differs.
                // TODO(post-gloas): remove this conversion once mainnet has forked to Gloas.
                Attestation::Electra(a) => Some(AttestationGloas {
                    aggregation_bits: ProgressiveBitList::from_bytes(
                        a.aggregation_bits.into_bytes(),
                    )
                    .inspect_err(
                        |e| warn!(error = ?e, "Dropping attestation with invalid aggregation bits"),
                    )
                    .ok()?,
                    data: a.data,
                    signature: a.signature,
                    committee_bits: a.committee_bits,
                }),
                Attestation::Gloas(a) => Some(a),
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
    /// Return `(block, post_block_state, consensus_block_value, execution_payload_value,
    /// payload_contents, builder_url)` where:
    ///
    /// - `post_block_state` is the state post block application
    /// - `consensus_block_value` is the consensus-layer rewards for `block`
    /// - `execution_payload_value` is the wei value of the winning payload bid
    /// - `payload_contents` is the locally-built envelope, KZG proofs and blobs (`None` when
    ///   committing to a builder bid)
    /// - `builder_url` is the winning direct builder's URL (`None` for a self-build or p2p bid)
    #[instrument(skip_all, level = "debug")]
    fn complete_partial_beacon_block_gloas(
        &self,
        partial_beacon_block: PartialBeaconBlock<T::EthSpec>,
        winning_bid: BidCandidate<T::EthSpec>,
        parent_execution_requests: ExecutionRequestsGloas<T::EthSpec>,
        mut state: BeaconState<T::EthSpec>,
        verification: ProduceBlockVerification,
    ) -> Result<BlockProductionResult<T::EthSpec>, BlockProductionError> {
        // Read the reported value and `builder_url` (`Some` only for a direct bid, becoming the
        // `Eth-Builder-Url` header) before destructuring the candidate.
        let execution_payload_value = winning_bid.payload_value();
        let builder_url = winning_bid.builder_url().cloned();
        let BidCandidate {
            signed_bid, source, ..
        } = winning_bid;
        let signed_execution_payload_bid = (*signed_bid).clone();
        // `payload_data` (`Some` only for a local build) drives envelope construction below.
        let payload_data = match source {
            BidSource::Local { payload_data, .. } => Some(*payload_data),
            BidSource::Gossip | BidSource::Direct { .. } => None,
        };

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
                    // The operation list lengths are bounded by the op pool packing limits above.
                    proposer_slashings: ProgressiveVariableList::from_iter(proposer_slashings),
                    attester_slashings: ProgressiveVariableList::from_iter(attester_slashings),
                    attestations: ProgressiveVariableList::from_iter(attestations),
                    deposits: ProgressiveVariableList::from_iter(deposits),
                    voluntary_exits: ProgressiveVariableList::from_iter(voluntary_exits),
                    sync_aggregate,
                    bls_to_execution_changes: ProgressiveVariableList::from_iter(
                        bls_to_execution_changes,
                    ),
                    parent_execution_requests,
                    signed_execution_payload_bid,
                    payload_attestations: ProgressiveVariableList::from_iter(payload_attestations),
                    _phantom: PhantomData::<FullPayload<T::EthSpec>>,
                },
            }),
            // TODO(heze): construct a `BeaconBlockHeze` here once Heze block production is
            // wired up end-to-end (get_payload, envelope handling, etc).
            BeaconState::Heze(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Block production disabled for Heze".to_owned(),
                ));
            }
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
        let payload_contents = if let Some(payload_data) = payload_data {
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
            let (blobs, kzg_proofs) = payload_data.blobs_and_proofs;
            let envelope = Arc::new(signed_envelope.message);
            let blobs = Arc::new(blobs);
            self.pending_payload_envelopes
                .write()
                .insert(PendingEnvelopeData {
                    envelope: envelope.clone(),
                    blobs: Some(blobs.clone()),
                });

            debug!(
                %beacon_block_root,
                slot = %envelope_slot,
                "Cached pending execution payload envelope"
            );
            Some((envelope, kzg_proofs, blobs))
        } else {
            None
        };

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);

        trace!(
            parent = ?block.parent_root(),
            attestations = block.body().attestations_len(),
            slot = %block.slot(),
            "Produced beacon block"
        );

        Ok((
            block,
            state,
            consensus_block_value,
            execution_payload_value,
            payload_contents,
            builder_url,
        ))
    }

    /// Produce a self-build `ExecutionPayloadBid` for some `slot` upon the given `state`, building
    /// on `parent_block_hash` (the FULL/EMPTY parent execution hash the caller selected). This
    /// function assumes we've already advanced `state`.
    ///
    /// Borrows `state` (rather than consuming it) so the caller retains it if the local build fails
    /// and it needs to fall back to an external bid. Returns the signed bid and a `LocalBuildResult`
    /// carrying the payload data needed to construct the `ExecutionPayloadEnvelope` after the beacon
    /// block is created, plus the EL block value and `should_override_builder` flag used by the
    /// caller to compare against external builder bids.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    #[instrument(level = "debug", skip_all)]
    pub async fn produce_execution_payload_bid(
        self: Arc<Self>,
        state: &BeaconState<T::EthSpec>,
        parent_envelope: Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>,
        produce_at_slot: Slot,
        bid_value: u64,
        builder_index: BuilderIndex,
        parent_block_hash: ExecutionBlockHash,
    ) -> Result<
        (
            SignedExecutionPayloadBid<T::EthSpec>,
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

        let prepare_payload_handle = get_execution_payload_gloas(
            self.clone(),
            state,
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
            _phantom: PhantomData,
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
            LocalBuildResult {
                payload_data,
                payload_value,
                should_override_builder,
            },
        ))
    }

    /// Acquire the external payload-bid candidates for this proposal.
    ///
    /// Fans `getExecutionPayloadBid` out to every configured direct builder (validating each
    /// returned bid against `state` via [`verify_direct_bid`]), then reads the highest direct bid
    /// and the highest gossip-verified bid from their caches and returns them as external
    /// [`BidCandidate`]s for [`bid_selection::select_payload_bid`](super::bid_selection) to rank
    /// against the local build.
    ///
    /// Direct bids are requested only when there are configured builders to contact and the proposer
    /// submitted preferences to validate against (`proposer_preferences`, needed for a direct bid's
    /// gas limit and fee recipient). Acquisition is best-effort: any direct failure — including a
    /// missing builder service — is logged and skipped, never aborting block production, which can
    /// still proceed on the local build and gossip bids.
    async fn acquire_external_bid_candidates(
        self: &Arc<Self>,
        ctx: BidRequestContext,
        builder_config: &BuilderConfig,
        proposer_preferences: Option<&SignedProposerPreferences>,
        state: &BeaconState<T::EthSpec>,
    ) -> Vec<BidCandidate<T::EthSpec>> {
        let mut externals = Vec::new();

        // Direct bids: only when there are builders to contact and the proposer submitted preferences
        // to validate against.
        if !builder_config.builders.is_empty() {
            if let Some(proposer_preferences) = proposer_preferences {
                externals.extend(
                    self.acquire_direct_bid_candidates(
                        &ctx,
                        builder_config,
                        proposer_preferences,
                        state,
                    )
                    .await,
                );
            } else {
                // Direct bids can't be validated without the proposer's fee recipient / gas-limit
                // target, so builders configured with no available preferences are skipped.
                warn!(
                    "Builders are configured but no proposer preferences are available; skipping \
                     direct builder bids for this proposal"
                );
            }
        }

        if let Some(gossip_bid) = self.gossip_verified_payload_bid_cache.get_highest_bid(
            ctx.slot,
            BidParent {
                parent_block_hash: ctx.parent_hash,
                parent_block_root: ctx.parent_root,
            },
        ) {
            // The gossip bid was validated against the head state at gossip time; its builder's
            // eligibility or coverage can go stale before production. Re-check against the production
            // state and drop it if it would now fail `per_block_processing`, so a stale gossip bid
            // can't outrank a viable candidate and sink the whole proposal.
            match verify_bid_state_conditions(&gossip_bid.message, state, &self.spec) {
                Ok(_) => {
                    externals.push(BidCandidate::gossip(
                        gossip_bid,
                        builder_config.builder_boost_factor,
                        builder_config.min_bid,
                    ));
                }
                Err(error) => {
                    warn!(
                        ?error,
                        "Skipping gossip bid that no longer passes state validation"
                    );
                }
            }
        }

        externals
    }

    /// Request direct bids from the configured builders and return each valid one as a selection
    /// candidate.
    ///
    /// Best-effort and never fatal: the builder service is constructed whenever the Gloas fork is
    /// scheduled, so in a correctly-built node it is always present on this (Gloas) path — a missing
    /// service is an unexpected construction bug. Either way it is logged and skipped rather than
    /// aborting block production. Per-builder request/validation failures are handled inside
    /// [`request_and_validate_bids`](builder_client::Builders::request_and_validate_bids).
    async fn acquire_direct_bid_candidates(
        self: &Arc<Self>,
        ctx: &BidRequestContext,
        builder_config: &BuilderConfig,
        proposer_preferences: &SignedProposerPreferences,
        state: &BeaconState<T::EthSpec>,
    ) -> Vec<BidCandidate<T::EthSpec>> {
        let Some(builders) = self.builders.as_ref() else {
            error!(
                "Builder service unexpectedly absent during Gloas block production (it is built \
                 whenever the Gloas fork is scheduled); skipping direct bids for this proposal"
            );
            return Vec::new();
        };

        let slot = ctx.slot;
        let parent_hash = ctx.parent_hash;
        let parent_root = ctx.parent_root;

        // Clone the production state once and share it across the concurrent per-builder
        // verifications via `Arc`. The clone converts the `&BeaconState` borrow into an owned value
        // the blocking tasks can hold (they must be `'static`, so they can't borrow this scope);
        // it's a milhouse structural share (refcount bumps, not a copy of the validator set), so it's
        // cheap. Each builder's task then just clones these `Arc`s.
        let state = Arc::new(state.clone());
        let spec = self.spec.clone();
        let proposer_preferences = Arc::new(proposer_preferences.clone());
        let executor = self.task_executor.clone();

        // Fan `getExecutionPayloadBid` out to the configured builders, validating each returned bid
        // against the production state, then turn each valid bid into a `Direct` selection candidate.
        builders
            .request_and_validate_bids(
                ctx,
                &builder_config.builders,
                move |signed_bid, expected_builder_pubkeys| {
                    let state = state.clone();
                    let spec = spec.clone();
                    let proposer_preferences = proposer_preferences.clone();
                    let executor = executor.clone();
                    async move {
                        // The bid's BLS signature check is CPU-bound; run the whole verification on a
                        // blocking thread so it doesn't stall the async executor during the proposal
                        // path. Runtime-shutdown / join failures are surfaced as `InternalError`,
                        // which `request_and_validate_bids` logs and skips like any other bid failure.
                        executor
                            .spawn_blocking_handle(
                                move || {
                                    verify_direct_bid(
                                        &signed_bid,
                                        slot,
                                        parent_hash,
                                        parent_root,
                                        &expected_builder_pubkeys,
                                        &proposer_preferences,
                                        &state,
                                        &spec,
                                    )
                                },
                                "verify_direct_bid",
                            )
                            .ok_or_else(|| {
                                PayloadBidError::InternalError("runtime shutting down".to_string())
                            })?
                            .await
                            .map_err(|e| {
                                PayloadBidError::InternalError(format!(
                                    "verify_direct_bid task failed: {e}"
                                ))
                            })?
                    }
                },
            )
            .await
            .into_iter()
            .map(|direct| {
                BidCandidate::direct(
                    direct.signed_bid,
                    direct.builder_boost_factor,
                    direct.max_execution_payment,
                    direct.min_bid,
                    direct.builder_url,
                )
            })
            .collect()
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

    let parent_bid = state.latest_execution_payload_bid()?;
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
    let target_gas_limit = execution_layer
        .get_proposer_gas_limit(proposer_index)
        .await
        .or_else(|| {
            spec.get_scheduled_gas_limit(builder_params.slot.epoch(T::EthSpec::slots_per_epoch()))
        })
        .unwrap_or(DEFAULT_GAS_LIMIT);

    let payload_attributes = PayloadAttributes::new(
        timestamp,
        random,
        suggested_fee_recipient,
        Some(withdrawals),
        Some(parent_beacon_block_root),
        slot_number,
        Some(target_gas_limit),
    );
    let payload_parameters = PayloadParameters {
        parent_hash: parent_block_hash,
        parent_gas_limit: None,
        proposer_gas_limit: Some(target_gas_limit),
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
    parent_execution_requests: &ExecutionRequestsGloas<E>,
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
    use ssz_types::ProgressiveVariableList;
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
    ) -> ExecutionRequestsGloas<TestSpec> {
        ExecutionRequestsGloas {
            deposits: ProgressiveVariableList::empty(),
            withdrawals: ProgressiveVariableList::new(withdrawals),
            consolidations: ProgressiveVariableList::new(consolidations),
            builder_deposits: ProgressiveVariableList::empty(),
            builder_exits: ProgressiveVariableList::empty(),
            _phantom: PhantomData,
        }
    }

    fn run_filter(
        exits: &mut Vec<SignedVoluntaryExit>,
        requests: &ExecutionRequestsGloas<TestSpec>,
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
}

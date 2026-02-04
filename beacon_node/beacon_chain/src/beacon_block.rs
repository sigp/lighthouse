use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::u64;

use bls::Signature;
use operation_pool::CompactAttestationRef;
use ssz::Encode;
use state_processing::common::get_attesting_indices_from_state;
use state_processing::epoch_cache::initialize_epoch_cache;
use state_processing::per_block_processing::verify_attestation_for_block_inclusion;
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
};
use state_processing::{VerifyOperation, state_advance::complete_state_advance};
use tracing::{Span, debug, debug_span, error, trace, warn};
use types::{
    Attestation, AttestationElectra, AttesterSlashing, AttesterSlashingElectra, BeaconBlock,
    BeaconBlockBodyGloas, BeaconBlockGloas, BeaconState, Deposit, Eth1Data, EthSpec, FullPayload,
    Graffiti, Hash256, PayloadAttestation, ProposerSlashing, RelativeEpoch, SignedBeaconBlock,
    SignedBlsToExecutionChange, SignedExecutionPayloadBid, SignedVoluntaryExit, Slot,
    SyncAggregate,
};

use crate::{
    BeaconChain, BeaconChainTypes, BlockProductionError, ProduceBlockVerification,
    graffiti_calculator::GraffitiSettings, metrics,
};

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
    sync_aggregate: Option<SyncAggregate<E>>,
    bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
}

// We'll need to add that once we include trusted/trustless bids
impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn produce_block_with_verification_gloas(
        self: &Arc<Self>,
        randao_reveal: Signature,
        slot: Slot,
        graffiti_settings: GraffitiSettings,
        verification: ProduceBlockVerification,
        _builder_boost_factor: Option<u64>,
    ) -> Result<
        (
            BeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
            BeaconState<T::EthSpec>,
            u64,
        ),
        BlockProductionError,
    > {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let _complete_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);
        // Part 1/2 (blocking)
        //
        // Load the parent state from disk.
        let chain = self.clone();
        let span = Span::current();
        let (state, state_root_opt) = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    let _guard =
                        debug_span!(parent: span, "load_state_for_block_production").entered();
                    chain.load_state_for_block_production(slot)
                },
                "load_state_for_block_production",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        // Part 2/2 (async, with some blocking components)
        //
        // Produce the block upon the state
        self.produce_block_on_state_gloas(
            state,
            state_root_opt,
            slot,
            randao_reveal,
            graffiti_settings,
            verification,
        )
        .await
    }

    // TODO(gloas) need to implement builder boost factor logic
    pub async fn produce_block_on_state_gloas(
        self: &Arc<Self>,
        state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        graffiti_settings: GraffitiSettings,
        verification: ProduceBlockVerification,
    ) -> Result<
        (
            BeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
            BeaconState<T::EthSpec>,
            u64,
        ),
        BlockProductionError,
    > {
        // Part 1/3 (blocking)
        //
        // Perform the state advance and block-packing functions.
        let chain = self.clone();
        let graffiti = self
            .graffiti_calculator
            .get_graffiti(graffiti_settings)
            .await;
        let span = Span::current();
        let (partial_beacon_block, state) = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    let _guard =
                        debug_span!(parent: span, "produce_partial_beacon_block_gloas").entered();
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

        // Part 2/3 (async)
        //
        // Produce the execution payload bid.
        // TODO(gloas) this is strictly for building local bids
        // We'll need to build out trustless/trusted bid paths.
        let (execution_payload_bid, state) = self
            .clone()
            .produce_execution_payload_bid(state, state_root_opt, produce_at_slot, 0, u64::MAX)
            .await?;

        // Part 3/3 (blocking)
        //
        // Complete the block with the execution payload bid.
        let chain = self.clone();
        let span = Span::current();
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    let _guard =
                        debug_span!(parent: span, "complete_partial_beacon_block_gloas").entered();
                    chain.complete_partial_beacon_block_gloas(
                        partial_beacon_block,
                        execution_payload_bid,
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

        // TODO(gloas)
        // let slot_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_SLOT_PROCESS_TIMES);

        // Ensure the state has performed a complete transition into the required slot.
        complete_state_advance(&mut state, state_root_opt, produce_at_slot, &self.spec)?;

        // TODO(gloas)
        // drop(slot_timer);

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
            // TODO(gloas)
            // let _unagg_import_timer =
            // metrics::start_timer(&metrics::BLOCK_PRODUCTION_UNAGGREGATED_TIMES);
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
            // TODO(gloas)
            // let _attestation_packing_timer =
            //    metrics::start_timer(&metrics::BLOCK_PRODUCTION_ATTESTATION_TIMES);

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
                            "Attempted to include an invalid proposer slashing"
                        );
                    })
                    .is_ok()
            });

            // TODO(gloas) verifiy payload attestation signature here as well
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

        let sync_aggregate = if matches!(&state, BeaconState::Base(_)) {
            None
        } else {
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
            Some(sync_aggregate)
        };

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

    fn complete_partial_beacon_block_gloas(
        &self,
        partial_beacon_block: PartialBeaconBlock<T::EthSpec>,
        signed_execution_payload_bid: SignedExecutionPayloadBid<T::EthSpec>,
        mut state: BeaconState<T::EthSpec>,
        verification: ProduceBlockVerification,
    ) -> Result<
        (
            BeaconBlock<T::EthSpec, FullPayload<T::EthSpec>>,
            BeaconState<T::EthSpec>,
            u64,
        ),
        BlockProductionError,
    > {
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
            BeaconState::Base(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Altair(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Bellatrix(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Capella(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Deneb(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Electra(_) => {
                return Err(BlockProductionError::InvalidBlockVariant(
                    "Cannot construct a block pre-Gloas".to_owned(),
                ));
            }
            BeaconState::Fulu(_) => {
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
                    sync_aggregate: sync_aggregate
                        .ok_or(BlockProductionError::MissingSyncAggregate)?,
                    bls_to_execution_changes: bls_to_execution_changes
                        .try_into()
                        .map_err(BlockProductionError::SszTypesError)?,
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

        // TODO(gloas) ensure block size is measured from the signed block
        let block_size = signed_beacon_block.ssz_bytes_len();
        debug!(%block_size, "Produced block on state");

        // TODO(gloas)
        // metrics::observe(&metrics::BLOCK_SIZE, block_size as f64);

        if block_size > self.config.max_network_size {
            return Err(BlockProductionError::BlockTooLarge(block_size));
        }

        // TODO(gloas)
        // let process_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_PROCESS_TIMES);
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
        // TODO(gloas)
        // drop(process_timer);

        // TODO(gloas)
        //let state_root_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_ROOT_TIMES);

        let state_root = state.update_tree_hash_cache()?;

        // TODO(gloas)
        // drop(state_root_timer);

        let (mut block, _) = signed_beacon_block.deconstruct();
        *block.state_root_mut() = state_root;

        // TODO(gloas)
        // metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);

        trace!(
            parent = ?block.parent_root(),
            attestations = block.body().attestations_len(),
            slot = %block.slot(),
            "Produced beacon block"
        );

        Ok((block, state, consensus_block_value))
    }
}

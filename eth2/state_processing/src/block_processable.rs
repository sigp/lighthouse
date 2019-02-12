use crate::SlotProcessingError;
use hashing::hash;
use log::debug;
use ssz::{ssz_encode, TreeHash};
use types::{
    beacon_state::{AttestationValidationError, CommitteesError},
    AggregatePublicKey, Attestation, BeaconBlock, BeaconState, ChainSpec, Crosslink, Epoch, Exit,
    Fork, Hash256, PendingAttestation, PublicKey, Signature,
};

// TODO: define elsehwere.
const DOMAIN_PROPOSAL: u64 = 2;
const DOMAIN_EXIT: u64 = 3;
const DOMAIN_RANDAO: u64 = 4;
const PHASE_0_CUSTODY_BIT: bool = false;
const DOMAIN_ATTESTATION: u64 = 1;

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    StateAlreadyTransitioned,
    PresentSlotIsNone,
    UnableToDecodeBlock,
    MissingParentState(Hash256),
    InvalidParentState(Hash256),
    MissingBeaconBlock(Hash256),
    InvalidBeaconBlock(Hash256),
    MissingParentBlock(Hash256),
    NoBlockProducer,
    StateSlotMismatch,
    BadBlockSignature,
    BadRandaoSignature,
    MaxProposerSlashingsExceeded,
    BadProposerSlashing,
    MaxAttestationsExceeded,
    InvalidAttestation(AttestationValidationError),
    NoBlockRoot,
    MaxDepositsExceeded,
    MaxExitsExceeded,
    BadExit,
    BadCustodyReseeds,
    BadCustodyChallenges,
    BadCustodyResponses,
    CommitteesError(CommitteesError),
    SlotProcessingError(SlotProcessingError),
}

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

pub trait BlockProcessable {
    fn per_block_processing(&mut self, block: &BeaconBlock, spec: &ChainSpec) -> Result<(), Error>;
    fn per_block_processing_without_verifying_block_signature(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), Error>;
}

impl BlockProcessable for BeaconState {
    fn per_block_processing(&mut self, block: &BeaconBlock, spec: &ChainSpec) -> Result<(), Error> {
        per_block_processing_signature_optional(self, block, true, spec)
    }

    fn per_block_processing_without_verifying_block_signature(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        per_block_processing_signature_optional(self, block, false, spec)
    }
}

fn per_block_processing_signature_optional(
    state: &mut BeaconState,
    block: &BeaconBlock,
    verify_block_signature: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    ensure!(block.slot == state.slot, Error::StateSlotMismatch);

    /*
     * Proposer Signature
     */
    let block_proposer_index = state
        .get_beacon_proposer_index(block.slot, spec)
        .map_err(|_| Error::NoBlockProducer)?;
    let block_proposer = &state.validator_registry[block_proposer_index];

    if verify_block_signature {
        ensure!(
            bls_verify(
                &block_proposer.pubkey,
                &block.proposal_root(spec)[..],
                &block.signature,
                get_domain(&state.fork, state.current_epoch(spec), DOMAIN_PROPOSAL)
            ),
            Error::BadBlockSignature
        );
    }

    /*
     * RANDAO
     */
    ensure!(
        bls_verify(
            &block_proposer.pubkey,
            &ssz_encode(&state.current_epoch(spec)),
            &block.randao_reveal,
            get_domain(&state.fork, state.current_epoch(spec), DOMAIN_RANDAO)
        ),
        Error::BadRandaoSignature
    );

    // TODO: check this is correct.
    let new_mix = {
        let mut mix = state.latest_randao_mixes
            [state.slot.as_usize() % spec.latest_randao_mixes_length]
            .to_vec();
        mix.append(&mut ssz_encode(&block.randao_reveal));
        Hash256::from(&hash(&mix)[..])
    };

    state.latest_randao_mixes[state.slot.as_usize() % spec.latest_randao_mixes_length] = new_mix;

    /*
     * Eth1 data
     */
    // TODO: Eth1 data processing.

    /*
     * Proposer slashings
     */
    ensure!(
        block.body.proposer_slashings.len() as u64 <= spec.max_proposer_slashings,
        Error::MaxProposerSlashingsExceeded
    );
    for proposer_slashing in &block.body.proposer_slashings {
        let proposer = state
            .validator_registry
            .get(proposer_slashing.proposer_index as usize)
            .ok_or(Error::BadProposerSlashing)?;
        ensure!(
            proposer_slashing.proposal_data_1.slot == proposer_slashing.proposal_data_2.slot,
            Error::BadProposerSlashing
        );
        ensure!(
            proposer_slashing.proposal_data_1.shard == proposer_slashing.proposal_data_2.shard,
            Error::BadProposerSlashing
        );
        ensure!(
            proposer_slashing.proposal_data_1.block_root
                != proposer_slashing.proposal_data_2.block_root,
            Error::BadProposerSlashing
        );
        ensure!(
            proposer.penalized_epoch > state.current_epoch(spec),
            Error::BadProposerSlashing
        );
        ensure!(
            bls_verify(
                &proposer.pubkey,
                &proposer_slashing.proposal_data_1.hash_tree_root(),
                &proposer_slashing.proposal_signature_1,
                get_domain(
                    &state.fork,
                    proposer_slashing
                        .proposal_data_1
                        .slot
                        .epoch(spec.epoch_length),
                    DOMAIN_PROPOSAL
                )
            ),
            Error::BadProposerSlashing
        );
        ensure!(
            bls_verify(
                &proposer.pubkey,
                &proposer_slashing.proposal_data_2.hash_tree_root(),
                &proposer_slashing.proposal_signature_2,
                get_domain(
                    &state.fork,
                    proposer_slashing
                        .proposal_data_2
                        .slot
                        .epoch(spec.epoch_length),
                    DOMAIN_PROPOSAL
                )
            ),
            Error::BadProposerSlashing
        );
        state.penalize_validator(proposer_slashing.proposer_index as usize, spec)?;
    }

    /*
     * Attestations
     */
    ensure!(
        block.body.attestations.len() as u64 <= spec.max_attestations,
        Error::MaxAttestationsExceeded
    );

    for attestation in &block.body.attestations {
        validate_attestation(&state, attestation, spec)?;

        let pending_attestation = PendingAttestation {
            data: attestation.data.clone(),
            aggregation_bitfield: attestation.aggregation_bitfield.clone(),
            custody_bitfield: attestation.custody_bitfield.clone(),
            inclusion_slot: state.slot,
        };
        state.latest_attestations.push(pending_attestation);
    }

    debug!(
        "{} attestations verified & processed.",
        block.body.attestations.len()
    );

    /*
     * Deposits
     */
    ensure!(
        block.body.deposits.len() as u64 <= spec.max_deposits,
        Error::MaxDepositsExceeded
    );

    // TODO: process deposits.

    /*
     * Exits
     */
    ensure!(
        block.body.exits.len() as u64 <= spec.max_exits,
        Error::MaxExitsExceeded
    );

    for exit in &block.body.exits {
        let validator = state
            .validator_registry
            .get(exit.validator_index as usize)
            .ok_or(Error::BadExit)?;
        ensure!(
            validator.exit_epoch
                > state.get_entry_exit_effect_epoch(state.current_epoch(spec), spec),
            Error::BadExit
        );
        ensure!(state.current_epoch(spec) >= exit.epoch, Error::BadExit);
        let exit_message = {
            let exit_struct = Exit {
                epoch: exit.epoch,
                validator_index: exit.validator_index,
                signature: spec.empty_signature.clone(),
            };
            exit_struct.hash_tree_root()
        };
        ensure!(
            bls_verify(
                &validator.pubkey,
                &exit_message,
                &exit.signature,
                get_domain(&state.fork, exit.epoch, DOMAIN_EXIT)
            ),
            Error::BadProposerSlashing
        );
        state.initiate_validator_exit(exit.validator_index as usize);
    }

    debug!("State transition complete.");

    Ok(())
}

pub fn validate_attestation(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), AttestationValidationError> {
    validate_attestation_signature_optional(state, attestation, spec, true)
}

pub fn validate_attestation_without_signature(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), AttestationValidationError> {
    validate_attestation_signature_optional(state, attestation, spec, false)
}

fn validate_attestation_signature_optional(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
    verify_signature: bool,
) -> Result<(), AttestationValidationError> {
    ensure!(
        attestation.data.slot + spec.min_attestation_inclusion_delay <= state.slot,
        AttestationValidationError::IncludedTooEarly
    );
    ensure!(
        attestation.data.slot + spec.epoch_length >= state.slot,
        AttestationValidationError::IncludedTooLate
    );
    if attestation.data.slot >= state.current_epoch_start_slot(spec) {
        ensure!(
            attestation.data.justified_epoch == state.justified_epoch,
            AttestationValidationError::WrongJustifiedSlot
        );
    } else {
        ensure!(
            attestation.data.justified_epoch == state.previous_justified_epoch,
            AttestationValidationError::WrongJustifiedSlot
        );
    }
    ensure!(
        attestation.data.justified_block_root
            == *state
                .get_block_root(
                    attestation
                        .data
                        .justified_epoch
                        .start_slot(spec.epoch_length),
                    &spec
                )
                .ok_or(AttestationValidationError::NoBlockRoot)?,
        AttestationValidationError::WrongJustifiedRoot
    );
    let potential_crosslink = Crosslink {
        shard_block_root: attestation.data.shard_block_root,
        epoch: attestation.data.slot.epoch(spec.epoch_length),
    };
    ensure!(
        (attestation.data.latest_crosslink
            == state.latest_crosslinks[attestation.data.shard as usize])
            | (attestation.data.latest_crosslink == potential_crosslink),
        AttestationValidationError::BadLatestCrosslinkRoot
    );
    if verify_signature {
        let participants = state.get_attestation_participants(
            &attestation.data,
            &attestation.aggregation_bitfield,
            spec,
        )?;
        let mut group_public_key = AggregatePublicKey::new();
        for participant in participants {
            group_public_key.add(
                state.validator_registry[participant as usize]
                    .pubkey
                    .as_raw(),
            )
        }
        ensure!(
            attestation.verify_signature(
                &group_public_key,
                PHASE_0_CUSTODY_BIT,
                get_domain(
                    &state.fork,
                    attestation.data.slot.epoch(spec.epoch_length),
                    DOMAIN_ATTESTATION,
                )
            ),
            AttestationValidationError::BadSignature
        );
    }
    ensure!(
        attestation.data.shard_block_root == spec.zero_hash,
        AttestationValidationError::ShardBlockRootNotZero
    );
    Ok(())
}

fn get_domain(_fork: &Fork, _epoch: Epoch, _domain_type: u64) -> u64 {
    // TODO: stubbed out.
    0
}

fn bls_verify(pubkey: &PublicKey, message: &[u8], signature: &Signature, _domain: u64) -> bool {
    // TODO: add domain
    signature.verify(message, pubkey)
}

impl From<AttestationValidationError> for Error {
    fn from(e: AttestationValidationError) -> Error {
        Error::InvalidAttestation(e)
    }
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}

impl From<SlotProcessingError> for Error {
    fn from(e: SlotProcessingError) -> Error {
        Error::SlotProcessingError(e)
    }
}

use crate::{
    beacon_state::{AttestationValidationError, CommitteesError, SlotProcessingError},
    readers::BeaconBlockReader,
    BeaconBlock, BeaconState, ChainSpec, Exit, Fork, Hash256, PendingAttestation,
};
use bls::{PublicKey, Signature};
use hashing::hash;
use log::debug;
use ssz::{ssz_encode, TreeHash};

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

// TODO: define elsehwere.
const DOMAIN_PROPOSAL: u64 = 2;
const DOMAIN_EXIT: u64 = 3;
const DOMAIN_RANDAO: u64 = 4;

#[derive(Debug, PartialEq)]
pub enum Error {
    DBError(String),
    StateAlreadyTransitioned,
    NotImplemented,
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

impl BeaconState {
    pub fn per_block_processing(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        self.per_block_processing_signature_optional(block, true, spec)
    }

    pub fn per_block_processing_without_verifying_block_signature(
        &mut self,
        block: &BeaconBlock,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        self.per_block_processing_signature_optional(block, false, spec)
    }

    fn per_block_processing_signature_optional(
        &mut self,
        block: &BeaconBlock,
        verify_block_signature: bool,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        ensure!(block.slot() == self.slot, Error::StateSlotMismatch);

        /*
         * Proposer Signature
         */
        let block_proposer_index = self
            .get_beacon_proposer_index(block.slot, spec)
            .map_err(|_| Error::NoBlockProducer)?;
        let block_proposer = &self.validator_registry[block_proposer_index];

        if verify_block_signature {
            ensure!(
                bls_verify(
                    &block_proposer.pubkey,
                    &block.proposal_root(spec)[..],
                    &block.signature,
                    get_domain(&self.fork_data, self.slot, DOMAIN_PROPOSAL)
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
                &ssz_encode(&block_proposer.proposer_slots),
                &block.randao_reveal,
                get_domain(&self.fork_data, self.slot, DOMAIN_RANDAO)
            ),
            Error::BadRandaoSignature
        );

        // TODO: check this is correct.
        let new_mix = {
            let mut mix = self.latest_randao_mixes
                [(self.slot % spec.latest_randao_mixes_length) as usize]
                .to_vec();
            mix.append(&mut ssz_encode(&block.randao_reveal));
            Hash256::from(&hash(&mix)[..])
        };

        self.latest_randao_mixes[(self.slot % spec.latest_randao_mixes_length) as usize] = new_mix;

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
            let proposer = self
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
                proposer.penalized_slot > self.slot,
                Error::BadProposerSlashing
            );
            ensure!(
                bls_verify(
                    &proposer.pubkey,
                    &proposer_slashing.proposal_data_1.hash_tree_root(),
                    &proposer_slashing.proposal_signature_1,
                    get_domain(
                        &self.fork_data,
                        proposer_slashing.proposal_data_1.slot,
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
                        &self.fork_data,
                        proposer_slashing.proposal_data_2.slot,
                        DOMAIN_PROPOSAL
                    )
                ),
                Error::BadProposerSlashing
            );
            penalize_validator(&self, proposer_slashing.proposer_index as usize);
        }

        /*
         * Attestations
         */
        ensure!(
            block.body.attestations.len() as u64 <= spec.max_attestations,
            Error::MaxAttestationsExceeded
        );

        for attestation in &block.body.attestations {
            self.validate_attestation(attestation, spec)?;

            let pending_attestation = PendingAttestation {
                data: attestation.data.clone(),
                aggregation_bitfield: attestation.aggregation_bitfield.clone(),
                custody_bitfield: attestation.custody_bitfield.clone(),
                slot_included: self.slot,
            };
            self.latest_attestations.push(pending_attestation);
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
            let validator = self
                .validator_registry
                .get(exit.validator_index as usize)
                .ok_or(Error::BadExit)?;
            ensure!(
                validator.exit_slot > self.slot + spec.entry_exit_delay,
                Error::BadExit
            );
            ensure!(self.slot >= exit.slot, Error::BadExit);
            let exit_message = {
                let exit_struct = Exit {
                    slot: exit.slot,
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
                    get_domain(&self.fork_data, exit.slot, DOMAIN_EXIT)
                ),
                Error::BadProposerSlashing
            );
            initiate_validator_exit(&self, exit.validator_index);
        }

        /*
         * Custody
         */
        ensure!(
            block.body.custody_reseeds.is_empty(),
            Error::BadCustodyReseeds
        );
        ensure!(
            block.body.custody_challenges.is_empty(),
            Error::BadCustodyChallenges
        );
        ensure!(
            block.body.custody_responses.is_empty(),
            Error::BadCustodyResponses
        );

        debug!("State transition complete.");

        Ok(())
    }
}

fn initiate_validator_exit(_state: &BeaconState, _index: u32) {
    // TODO: stubbed out.
}

fn penalize_validator(_state: &BeaconState, _proposer_index: usize) {
    // TODO: stubbed out.
}

fn get_domain(_fork: &Fork, _slot: u64, _domain_type: u64) -> u64 {
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

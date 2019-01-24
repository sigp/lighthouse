use super::{BeaconChain, ClientDB, DBError, SlotClock};
use bls::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use boolean_bitfield::BooleanBitfield;
use slot_clock::{SystemTimeSlotClockError, TestingSlotClockError};
use ssz::ssz_encode;
use types::{
    readers::BeaconBlockReader, AttestationData, AttestationDataAndCustodyBit, BeaconBlock,
    BeaconState, Exit, Fork, Hash256, PendingAttestation, ProposalSignedData,
};

// TODO: define elsehwere.
const DOMAIN_ATTESTATION: u64 = 1;
const DOMAIN_PROPOSAL: u64 = 2;
const DOMAIN_EXIT: u64 = 3;
const DOMAIN_RANDAO: u64 = 4;

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

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
    BadAttestation,
    NoBlockRoot,
    MaxDepositsExceeded,
    MaxExitsExceeded,
    BadExit,
    BadCustodyReseeds,
    BadCustodyChallenges,
    BadCustodyResponses,
    SlotClockError(SystemTimeSlotClockError),
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn state_transition(
        &self,
        mut state: BeaconState,
        block: &BeaconBlock,
    ) -> Result<BeaconState, Error> {
        ensure!(state.slot < block.slot, Error::StateAlreadyTransitioned);

        for _ in state.slot..block.slot {
            self.per_slot_processing(&mut state, &block.parent_root)?;
        }

        /*
         * Slot
         */

        ensure!(block.slot() == state.slot, Error::StateSlotMismatch);

        /*
         * Proposer Signature
         */

        let block_without_signature_root = {
            let mut block_without_signature = block.clone();
            block_without_signature.signature = self.spec.empty_signature.clone();
            block_without_signature.canonical_root()
        };

        let proposal_root = {
            let proposal = ProposalSignedData {
                slot: state.slot,
                shard: self.spec.beacon_chain_shard_number,
                block_root: block_without_signature_root,
            };
            hash_tree_root(&proposal)
        };

        let block_proposer_index =
            get_beacon_proposer_index(&state, block.slot, self.spec.epoch_length)
                .ok_or(Error::NoBlockProducer)?;
        let block_proposer = &state.validator_registry[block_proposer_index];

        ensure!(
            bls_verify(
                &block_proposer.pubkey,
                &proposal_root,
                &block.signature,
                get_domain(&state.fork_data, state.slot, DOMAIN_PROPOSAL)
            ),
            Error::BadBlockSignature
        );

        /*
         * RANDAO
         */

        ensure!(
            bls_verify(
                &block_proposer.pubkey,
                &ssz_encode(&block_proposer.proposer_slots),
                &block.randao_reveal,
                get_domain(&state.fork_data, state.slot, DOMAIN_RANDAO)
            ),
            Error::BadRandaoSignature
        );

        let new_mix = {
            let mut mix = state.latest_randao_mixes
                [(state.slot % self.spec.latest_randao_mixes_length) as usize]
                .to_vec();
            mix.append(&mut ssz_encode(&block.randao_reveal));
            hash(&mix)
        };

        state.latest_randao_mixes[(state.slot % self.spec.latest_randao_mixes_length) as usize] =
            new_mix;

        /*
         * Eth1 data
         */

        // TODO: Eth1 data stuff.

        /*
         * OPERATIONS
         */

        /*
         * Proposer slashings
         */

        ensure!(
            block.body.proposer_slashings.len() as u64 <= self.spec.max_proposer_slashings,
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
                proposer.penalized_slot > state.slot,
                Error::BadProposerSlashing
            );
            ensure!(
                bls_verify(
                    &proposer.pubkey,
                    &hash_tree_root(&proposer_slashing.proposal_data_1),
                    &proposer_slashing.proposal_signature_1,
                    get_domain(
                        &state.fork_data,
                        proposer_slashing.proposal_data_1.slot,
                        DOMAIN_PROPOSAL
                    )
                ),
                Error::BadProposerSlashing
            );
            ensure!(
                bls_verify(
                    &proposer.pubkey,
                    &hash_tree_root(&proposer_slashing.proposal_data_2),
                    &proposer_slashing.proposal_signature_2,
                    get_domain(
                        &state.fork_data,
                        proposer_slashing.proposal_data_2.slot,
                        DOMAIN_PROPOSAL
                    )
                ),
                Error::BadProposerSlashing
            );
            penalize_validator(&state, proposer_slashing.proposer_index as usize);
        }

        /*
         * Attestations
         */
        ensure!(
            block.body.attestations.len() as u64 <= self.spec.max_attestations,
            Error::MaxAttestationsExceeded
        );

        for attestation in &block.body.attestations {
            ensure!(
                attestation.data.slot + self.spec.min_attestation_inclusion_delay <= state.slot,
                Error::BadAttestation
            );
            ensure!(
                attestation.data.slot + self.spec.epoch_length >= state.slot,
                Error::BadAttestation
            );
            if state.justified_slot >= state.slot - (state.slot % self.spec.epoch_length) {
                ensure!(
                    attestation.data.justified_slot == state.justified_slot,
                    Error::BadAttestation
                );
            } else {
                ensure!(
                    attestation.data.justified_slot == state.previous_justified_slot,
                    Error::BadAttestation
                );
            }
            ensure!(
                attestation.data.justified_block_root
                    == *get_block_root(
                        &state,
                        attestation.data.justified_slot,
                        self.spec.latest_block_roots_length
                    )
                    .ok_or(Error::NoBlockRoot)?,
                Error::BadAttestation
            );
            ensure!(
                (attestation.data.latest_crosslink_root
                    == state.latest_crosslinks[attestation.data.shard as usize].shard_block_root)
                    || (attestation.data.shard_block_root
                        == state.latest_crosslinks[attestation.data.shard as usize]
                            .shard_block_root),
                Error::BadAttestation
            );
            let participants = get_attestation_participants(
                &state,
                &attestation.data,
                &attestation.aggregation_bitfield,
            );
            let mut group_public_key = AggregatePublicKey::new();
            for participant in participants {
                group_public_key.add(
                    state.validator_registry[participant as usize]
                        .pubkey
                        .as_raw(),
                )
            }
            let attestation_message = {
                let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
                    data: attestation.data.clone(),
                    custody_bit: false,
                };
                hash_tree_root(&attestation_data_and_custody_bit).to_vec()
            };
            // Signature verification.
            ensure!(
                bls_verify_aggregate(
                    &group_public_key,
                    &attestation_message[..],
                    &attestation.aggregate_signature,
                    get_domain(&state.fork_data, attestation.data.slot, DOMAIN_ATTESTATION)
                ),
                Error::BadProposerSlashing
            );
            ensure!(
                attestation.data.shard_block_root == self.spec.zero_hash,
                Error::BadAttestation
            );
            let pending_attestation = PendingAttestation {
                data: attestation.data.clone(),
                aggregation_bitfield: attestation.aggregation_bitfield.clone(),
                custody_bitfield: attestation.custody_bitfield.clone(),
                slot_included: state.slot,
            };
            state.latest_attestations.push(pending_attestation);
        }

        /*
         * Deposits
         */
        ensure!(
            block.body.deposits.len() as u64 <= self.spec.max_deposits,
            Error::MaxDepositsExceeded
        );

        // TODO: process deposits.

        /*
         * Exits
         */

        ensure!(
            block.body.exits.len() as u64 <= self.spec.max_exits,
            Error::MaxExitsExceeded
        );

        for exit in &block.body.exits {
            let validator = state
                .validator_registry
                .get(exit.validator_index as usize)
                .ok_or(Error::BadExit)?;
            ensure!(
                validator.exit_slot > state.slot + self.spec.entry_exit_delay,
                Error::BadExit
            );
            ensure!(state.slot >= exit.slot, Error::BadExit);
            let exit_message = {
                let exit_struct = Exit {
                    slot: exit.slot,
                    validator_index: exit.validator_index,
                    signature: self.spec.empty_signature.clone(),
                };
                hash_tree_root(&exit_struct)
            };
            ensure!(
                bls_verify(
                    &validator.pubkey,
                    &exit_message,
                    &exit.signature,
                    get_domain(&state.fork_data, exit.slot, DOMAIN_EXIT)
                ),
                Error::BadProposerSlashing
            );
            initiate_validator_exit(&state, exit.validator_index);
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

        Ok(state)
    }

    fn per_slot_processing(
        &self,
        state: &mut BeaconState,
        previous_block_root: &Hash256,
    ) -> Result<(), Error> {
        let epoch_length = self.spec.epoch_length;
        let latest_randao_mixes_length = self.spec.latest_randao_mixes_length;
        let latest_block_roots_length = self.spec.latest_block_roots_length;

        // Misc counters.
        state.slot += 1;
        let block_proposer = get_beacon_proposer_index(&state, state.slot, epoch_length)
            .ok_or(Error::NoBlockProducer)?;
        state.validator_registry[block_proposer].proposer_slots += 1;
        state.latest_randao_mixes[(state.slot % latest_randao_mixes_length) as usize] =
            state.latest_randao_mixes[((state.slot - 1) % latest_randao_mixes_length) as usize];

        // Block roots.
        state.latest_block_roots
            [((state.slot - 1) % self.spec.latest_block_roots_length) as usize] =
            *previous_block_root;

        if state.slot % latest_block_roots_length == 0 {
            let root = merkle_root(&state.latest_block_roots[..]);
            state.batched_block_roots.push(root);
        }
        Ok(())
    }
}

fn initiate_validator_exit(_state: &BeaconState, _index: u32) {
    // TODO: stubbed out.
}

fn get_attestation_participants(
    _state: &BeaconState,
    _attestation_data: &AttestationData,
    _aggregation_bitfield: &BooleanBitfield,
) -> Vec<usize> {
    vec![0, 1]
}

fn get_block_root(
    state: &BeaconState,
    slot: u64,
    latest_block_roots_length: u64,
) -> Option<&Hash256> {
    // TODO: test
    if state.slot <= slot + latest_block_roots_length && slot <= state.slot {
        state
            .latest_block_roots
            .get((slot % latest_block_roots_length) as usize)
    } else {
        None
    }
}

fn penalize_validator(_state: &BeaconState, _proposer_index: usize) {
    // TODO: stubbed out.
}

fn hash<T>(_input: &T) -> Hash256 {
    // TODO: stubbed out.
    Hash256::zero()
}

fn get_domain(_fork: &Fork, _slot: u64, _domain_type: u64) -> u64 {
    // TODO: stubbed out.
    0
}

fn bls_verify(_pubkey: &PublicKey, _message: &[u8], _signature: &Signature, _domain: u64) -> bool {
    // TODO: stubbed out.
    true
}

fn bls_verify_aggregate(
    _pubkey: &AggregatePublicKey,
    _message: &[u8],
    _signature: &AggregateSignature,
    _domain: u64,
) -> bool {
    // TODO: stubbed out.
    true
}

fn hash_tree_root<T>(_input: &T) -> Hash256 {
    // TODO: stubbed out.
    Hash256::zero()
}

fn merkle_root(_input: &[Hash256]) -> Hash256 {
    // TODO: stubbed out.
    Hash256::zero()
}

fn get_beacon_proposer_index(
    _state: &BeaconState,
    _slot: u64,
    _epoch_length: u64,
) -> Option<usize> {
    // TODO: stubbed out.
    Some(0)
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<TestingSlotClockError> for Error {
    fn from(_: TestingSlotClockError) -> Error {
        unreachable!(); // Testing clock never throws an error.
    }
}

impl From<SystemTimeSlotClockError> for Error {
    fn from(e: SystemTimeSlotClockError) -> Error {
        Error::SlotClockError(e)
    }
}

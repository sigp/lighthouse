use self::verify_proposer_slashing::verify_proposer_slashing;
use crate::errors::{BlockInvalid as Invalid, BlockProcessingError as Error, IntoWithIndex};
use hashing::hash;
use log::debug;
use ssz::{ssz_encode, SignedRoot, TreeHash};
use types::*;

pub use self::verify_attester_slashing::verify_attester_slashing;
pub use validate_attestation::{validate_attestation, validate_attestation_without_signature};
pub use verify_deposit::verify_deposit;
pub use verify_exit::verify_exit;
pub use verify_transfer::verify_transfer;

mod validate_attestation;
mod verify_attester_slashing;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;
mod verify_slashable_attestation;
mod verify_transfer;

pub fn per_block_processing(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    per_block_processing_signature_optional(state, block, true, spec)
}

pub fn per_block_processing_without_verifying_block_signature(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    per_block_processing_signature_optional(state, block, false, spec)
}

fn per_block_processing_signature_optional(
    mut state: &mut BeaconState,
    block: &BeaconBlock,
    should_verify_block_signature: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Verify that `block.slot == state.slot`.
    verify!(block.slot == state.slot, Invalid::StateSlotMismatch);

    // Get the epoch for future ergonomics.
    let epoch = block.slot.epoch(spec.slots_per_epoch);

    // Ensure the current epoch cache is built.
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;

    // Let `proposer = state.validator_registry[get_beacon_proposer_index(state, state.slot)]`.
    let block_proposer =
        &state.validator_registry[state.get_beacon_proposer_index(block.slot, spec)?];

    // Block signature
    if should_verify_block_signature {
        verify!(
            verify_block_signature(&block, &block_proposer, &state.fork, spec,),
            Invalid::BadSignature
        );
    }

    // Randao

    // Verify that `bls_verify(pubkey=proposer.pubkey,
    // message_hash=hash_tree_root(get_current_epoch(state)), signature=block.randao_reveal,
    // domain=get_domain(state.fork, get_current_epoch(state), DOMAIN_RANDAO))`.
    verify!(
        block.randao_reveal.verify(
            &state.current_epoch(spec).hash_tree_root()[..],
            spec.get_domain(epoch, Domain::Randao, &state.fork),
            &block_proposer.pubkey
        ),
        Invalid::BadRandaoSignature
    );

    // Update the state's RANDAO mix with the one revealed in the block.
    update_randao(&mut state, &block.randao_reveal, spec)?;

    // Eth1 Data

    // Either increment the eth1_data vote count, or add a new eth1_data.
    let matching_eth1_vote_index = state
        .eth1_data_votes
        .iter()
        .position(|vote| vote.eth1_data == block.eth1_data);
    if let Some(index) = matching_eth1_vote_index {
        state.eth1_data_votes[index].vote_count += 1;
    } else {
        state.eth1_data_votes.push(Eth1DataVote {
            eth1_data: block.eth1_data.clone(),
            vote_count: 1,
        });
    }

    //Proposer slashings

    verify!(
        block.body.proposer_slashings.len() as u64 <= spec.max_proposer_slashings,
        Invalid::MaxProposerSlashingsExceeded
    );
    for (i, proposer_slashing) in block.body.proposer_slashings.iter().enumerate() {
        verify_proposer_slashing(proposer_slashing, &state, spec)
            .map_err(|e| e.into_with_index(i))?;
        state.slash_validator(proposer_slashing.proposer_index as usize, spec)?;
    }

    // Attester Slashings

    verify!(
        block.body.attester_slashings.len() as u64 <= spec.max_attester_slashings,
        Invalid::MaxAttesterSlashingsExceed
    );
    for (i, attester_slashing) in block.body.attester_slashings.iter().enumerate() {
        let slashable_indices = verify_attester_slashing(&state, &attester_slashing, spec)
            .map_err(|e| e.into_with_index(i))?;
        for i in slashable_indices {
            state.slash_validator(i as usize, spec)?;
        }
    }

    // Attestations

    verify!(
        block.body.attestations.len() as u64 <= spec.max_attestations,
        Invalid::MaxAttestationsExceeded
    );
    for (i, attestation) in block.body.attestations.iter().enumerate() {
        // Build the previous epoch cache only if required by an attestation.
        if attestation.data.slot.epoch(spec.slots_per_epoch) == state.previous_epoch(spec) {
            state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
        }

        validate_attestation(&mut state, attestation, spec).map_err(|e| e.into_with_index(i))?;

        let pending_attestation = PendingAttestation {
            data: attestation.data.clone(),
            aggregation_bitfield: attestation.aggregation_bitfield.clone(),
            custody_bitfield: attestation.custody_bitfield.clone(),
            inclusion_slot: state.slot,
        };
        state.latest_attestations.push(pending_attestation);
    }

    // Deposits

    verify!(
        block.body.deposits.len() as u64 <= spec.max_deposits,
        Invalid::MaxDepositsExceeded
    );
    for (i, deposit) in block.body.deposits.iter().enumerate() {
        verify_deposit(&mut state, deposit, spec).map_err(|e| e.into_with_index(i))?;

        state
            .process_deposit(
                deposit.deposit_data.deposit_input.pubkey.clone(),
                deposit.deposit_data.amount,
                deposit
                    .deposit_data
                    .deposit_input
                    .proof_of_possession
                    .clone(),
                deposit.deposit_data.deposit_input.withdrawal_credentials,
                None,
                spec,
            )
            .map_err(|_| Error::Invalid(Invalid::DepositProcessingFailed(i)))?;

        state.deposit_index += 1;
    }

    // Exits

    verify!(
        block.body.voluntary_exits.len() as u64 <= spec.max_voluntary_exits,
        Invalid::MaxExitsExceeded
    );
    for (i, exit) in block.body.voluntary_exits.iter().enumerate() {
        verify_exit(&state, exit, spec).map_err(|e| e.into_with_index(i))?;

        state.initiate_validator_exit(exit.validator_index as usize);
    }

    // Transfers
    verify!(
        block.body.transfers.len() as u64 <= spec.max_transfers,
        Invalid::MaxTransfersExceed
    );
    for (i, transfer) in block.body.transfers.iter().enumerate() {
        verify_transfer(&state, transfer, spec).map_err(|e| e.into_with_index(i))?;

        let block_proposer = state.get_beacon_proposer_index(state.slot, spec)?;

        state.validator_balances[transfer.from as usize] -= transfer.amount + transfer.fee;
        state.validator_balances[transfer.to as usize] += transfer.amount + transfer.fee;
        state.validator_balances[block_proposer as usize] += transfer.fee;
    }

    debug!("State transition complete.");

    Ok(())
}

/// Verifies the signature of a block.
///
/// Spec v0.4.0
pub fn verify_block_signature(
    block: &BeaconBlock,
    block_proposer: &Validator,
    fork: &Fork,
    spec: &ChainSpec,
) -> bool {
    // Let proposal = `Proposal(block.slot, BEACON_CHAIN_SHARD_NUMBER, signed_root(block,
    // "signature"), block.signature)`.
    let proposal = Proposal {
        slot: block.slot,
        shard: spec.beacon_chain_shard_number,
        block_root: Hash256::from(&block.signed_root()[..]),
        signature: block.signature.clone(),
    };
    let domain = spec.get_domain(
        block.slot.epoch(spec.slots_per_epoch),
        Domain::Proposal,
        fork,
    );
    // Verify that `bls_verify(pubkey=proposer.pubkey, message_hash=signed_root(proposal,
    // "signature"), signature=proposal.signature, domain=get_domain(state.fork,
    // get_current_epoch(state), DOMAIN_PROPOSAL))`.
    proposal
        .signature
        .verify(&proposal.signed_root()[..], domain, &block_proposer.pubkey)
}

/// Updates the present randao mix.
///
/// Set `state.latest_randao_mixes[get_current_epoch(state) % LATEST_RANDAO_MIXES_LENGTH] =
/// xor(get_randao_mix(state, get_current_epoch(state)), hash(block.randao_reveal))`.
///
/// Spec v0.4.0
pub fn update_randao(
    state: &mut BeaconState,
    reveal: &Signature,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    let hashed_reveal = {
        let encoded_signature = ssz_encode(reveal);
        Hash256::from(&hash(&encoded_signature[..])[..])
    };

    let current_epoch = state.slot.epoch(spec.slots_per_epoch);

    let current_mix = state
        .get_randao_mix(current_epoch, spec)
        .ok_or_else(|| BeaconStateError::InsufficientRandaoMixes)?;

    let new_mix = *current_mix ^ hashed_reveal;

    let index = current_epoch.as_usize() % spec.latest_randao_mixes_length;

    if index < state.latest_randao_mixes.len() {
        state.latest_randao_mixes[index] = new_mix;
        Ok(())
    } else {
        Err(BeaconStateError::InsufficientRandaoMixes)
    }
}

#![cfg(all(test, not(feature = "fake_crypto")))]

use crate::per_block_processing;
use crate::per_block_processing::errors::{
    AttestationInvalid, AttesterSlashingInvalid, BlockOperationError, BlockProcessingError,
    DepositInvalid, HeaderInvalid, IndexedAttestationInvalid, IntoWithIndex,
    ProposerSlashingInvalid,
};
use crate::{
    per_block_processing::{process_operations, verify_exit::verify_exit},
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use lazy_static::lazy_static;
use ssz_types::Bitfield;
use test_utils::generate_deterministic_keypairs;
use types::*;

pub const MAX_VALIDATOR_COUNT: usize = 97;
pub const NUM_DEPOSITS: u64 = 1;
pub const VALIDATOR_COUNT: usize = 64;
pub const EPOCH_OFFSET: u64 = 4;
pub const NUM_ATTESTATIONS: u64 = 1;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(MAX_VALIDATOR_COUNT);
}

async fn get_harness<E: EthSpec>(
    epoch_offset: u64,
    num_validators: usize,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    // Set the state and block to be in the last slot of the `epoch_offset`th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + epoch_offset).end_slot(E::slots_per_epoch());
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .default_spec()
        .keypairs(KEYPAIRS[0..num_validators].to_vec())
        .fresh_ephemeral_store()
        .build();
    let state = harness.get_current_state();
    if last_slot_of_epoch > Slot::new(0) {
        harness
            .add_attested_blocks_at_slots(
                state,
                Hash256::zero(),
                (1..last_slot_of_epoch.as_u64())
                    .map(Slot::new)
                    .collect::<Vec<_>>()
                    .as_slice(),
                (0..num_validators).collect::<Vec<_>>().as_slice(),
            )
            .await;
    }
    harness
}

#[tokio::test]
async fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let state = harness.get_current_state();

    let slot = state.slot();
    let (block, mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &block,
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        &spec,
    );

    assert!(result.is_ok());
}

#[tokio::test]
async fn invalid_block_header_state_slot() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let state = harness.get_current_state();
    let slot = state.slot() + Slot::new(1);

    let (signed_block, mut state) = harness.make_block_return_pre_state(state, slot).await;
    let (mut block, signature) = signed_block.deconstruct();
    *block.slot_mut() = slot + Slot::new(1);

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, signature),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::StateSlotMismatch
        })
    );
}

#[tokio::test]
async fn invalid_parent_block_root() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let state = harness.get_current_state();
    let slot = state.slot();

    let (signed_block, mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;
    let (mut block, signature) = signed_block.deconstruct();
    *block.parent_root_mut() = Hash256::from([0xAA; 32]);

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, signature),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ParentBlockRootMismatch {
                state: state.latest_block_header().canonical_root(),
                block: Hash256::from([0xAA; 32])
            }
        })
    );
}

#[tokio::test]
async fn invalid_block_signature() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let state = harness.get_current_state();
    let slot = state.slot();
    let (signed_block, mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;
    let (block, _) = signed_block.deconstruct();

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, Signature::empty()),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        &spec,
    );

    // should get a BadSignature error
    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ProposalSignatureInvalid
        })
    );
}

#[tokio::test]
async fn invalid_randao_reveal_signature() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let state = harness.get_current_state();
    let slot = state.slot();

    let (signed_block, mut state) = harness
        .make_block_with_modifier(state, slot + 1, |block| {
            *block.body_mut().randao_reveal_mut() = Signature::empty();
        })
        .await;

    let mut ctxt = ConsensusContext::new(signed_block.slot());
    let result = per_block_processing(
        &mut state,
        &signed_block,
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        &spec,
    );

    // should get a BadRandaoSignature error
    assert_eq!(result, Err(BlockProcessingError::RandaoSignatureInvalid));
}

#[tokio::test]
async fn valid_4_deposits() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 4, None, None);
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;

    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);

    // Expecting Ok because these are valid deposits.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn invalid_deposit_deposit_count_too_big() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;

    let big_deposit_count = NUM_DEPOSITS + 1;
    state.eth1_data_mut().deposit_count = big_deposit_count;
    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);

    // Expecting DepositCountInvalid because we incremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: big_deposit_count as usize,
            found: 1
        })
    );
}

#[tokio::test]
async fn invalid_deposit_count_too_small() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;

    let small_deposit_count = NUM_DEPOSITS - 1;
    state.eth1_data_mut().deposit_count = small_deposit_count;
    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);

    // Expecting DepositCountInvalid because we decremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: small_deposit_count as usize,
            found: 1
        })
    );
}

#[tokio::test]
async fn invalid_deposit_bad_merkle_proof() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;
    let bad_index = state.eth1_deposit_index() as usize;

    // Manually offsetting deposit count and index to trigger bad merkle proof
    state.eth1_data_mut().deposit_count += 1;
    *state.eth1_deposit_index_mut() += 1;
    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);

    // Expecting BadMerkleProof because the proofs were created with different indices
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositInvalid {
            index: bad_index,
            reason: DepositInvalid::BadMerkleProof
        })
    );
}

#[tokio::test]
async fn invalid_deposit_wrong_sig() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) =
        harness.make_deposits(&mut state, 1, None, Some(SignatureBytes::empty()));
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;

    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);
    // Expecting Ok(()) even though the block signature does not correspond to the correct public key
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn invalid_deposit_invalid_pub_key() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut state = harness.get_current_state();

    let (deposits, state) =
        harness.make_deposits(&mut state, 1, Some(PublicKeyBytes::empty()), None);
    let deposits = VariableList::from(deposits);

    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block.to_mut().body_mut().deposits_mut() = deposits;

    let result = process_operations::process_deposits(state, head_block.body().deposits(), &spec);

    // Expecting Ok(()) even though we passed in invalid publickeybytes in the public key field of the deposit data.
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn invalid_attestation_no_committee_for_index() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block.to_mut().body_mut().attestations_mut()[0]
        .data
        .index += 1;
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting NoCommittee because we manually set the attestation's index to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadCommitteeIndex
        })
    );
}

#[tokio::test]
async fn invalid_attestation_wrong_justified_checkpoint() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    let old_justified_checkpoint = head_block.body().attestations()[0].data.source;
    let mut new_justified_checkpoint = old_justified_checkpoint;
    new_justified_checkpoint.epoch += Epoch::new(1);
    head_block.to_mut().body_mut().attestations_mut()[0]
        .data
        .source = new_justified_checkpoint;

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting WrongJustifiedCheckpoint because we manually set the
    // source field of the AttestationData object to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::WrongJustifiedCheckpoint {
                state: old_justified_checkpoint,
                attestation: new_justified_checkpoint,
                is_current: true,
            }
        })
    );
}

#[tokio::test]
async fn invalid_attestation_bad_aggregation_bitfield_len() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block.to_mut().body_mut().attestations_mut()[0].aggregation_bits =
        Bitfield::with_capacity(spec.target_committee_size).unwrap();

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting InvalidBitfield because the size of the aggregation_bitfield is bigger than the committee size.
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::InvalidBitfield
        ))
    );
}

#[tokio::test]
async fn invalid_attestation_bad_signature() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, 97).await; // minimal number of required validators for this test

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block.to_mut().body_mut().attestations_mut()[0].signature = AggregateSignature::empty();

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );
    // Expecting BadSignature because we're signing with invalid secret_keys
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadIndexedAttestation(
                IndexedAttestationInvalid::BadSignature
            )
        })
    );
}

#[tokio::test]
async fn invalid_attestation_included_too_early() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    let new_attesation_slot = head_block.body().attestations()[0].data.slot
        + Slot::new(MainnetEthSpec::slots_per_epoch());
    head_block.to_mut().body_mut().attestations_mut()[0]
        .data
        .slot = new_attesation_slot;

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting IncludedTooEarly because the shard included in the crosslink is bigger than expected
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::IncludedTooEarly {
                state: state.slot(),
                delay: spec.min_attestation_inclusion_delay,
                attestation: new_attesation_slot,
            }
        })
    );
}

#[tokio::test]
async fn invalid_attestation_included_too_late() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommittee
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    let new_attesation_slot = head_block.body().attestations()[0].data.slot
        - Slot::new(MainnetEthSpec::slots_per_epoch());
    head_block.to_mut().body_mut().attestations_mut()[0]
        .data
        .slot = new_attesation_slot;

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::IncludedTooLate {
                state: state.slot(),
                attestation: new_attesation_slot,
            }
        })
    );
}

#[tokio::test]
async fn invalid_attestation_target_epoch_slot_mismatch() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommittee
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block.to_mut().body_mut().attestations_mut()[0]
        .data
        .target
        .epoch += Epoch::new(1);

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::TargetEpochSlotMismatch {
                target_epoch: Epoch::new(EPOCH_OFFSET + 1),
                slot_epoch: Epoch::new(EPOCH_OFFSET),
            }
        })
    );
}

#[tokio::test]
async fn valid_insert_attester_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let attester_slashing = harness.make_attester_slashing(vec![1, 2]);

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        &[attester_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting Ok(()) because attester slashing is valid
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn invalid_attester_slashing_not_slashable() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    attester_slashing.attestation_1 = attester_slashing.attestation_2.clone();

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        &[attester_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting NotSlashable because the two attestations are the same
    assert_eq!(
        result,
        Err(BlockProcessingError::AttesterSlashingInvalid {
            index: 0,
            reason: AttesterSlashingInvalid::NotSlashable
        })
    );
}

#[tokio::test]
async fn invalid_attester_slashing_1_invalid() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    attester_slashing.attestation_1.attesting_indices = VariableList::from(vec![2, 1]);

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        &[attester_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    assert_eq!(
        result,
        Err(
            BlockOperationError::Invalid(AttesterSlashingInvalid::IndexedAttestation1Invalid(
                BlockOperationError::Invalid(
                    IndexedAttestationInvalid::BadValidatorIndicesOrdering(0)
                )
            ))
            .into_with_index(0)
        )
    );
}

#[tokio::test]
async fn invalid_attester_slashing_2_invalid() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    attester_slashing.attestation_2.attesting_indices = VariableList::from(vec![2, 1]);

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        &[attester_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    assert_eq!(
        result,
        Err(
            BlockOperationError::Invalid(AttesterSlashingInvalid::IndexedAttestation2Invalid(
                BlockOperationError::Invalid(
                    IndexedAttestationInvalid::BadValidatorIndicesOrdering(0)
                )
            ))
            .into_with_index(0)
        )
    );
}

#[tokio::test]
async fn valid_insert_proposer_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let proposer_slashing = harness.make_proposer_slashing(1);
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );
    // Expecting Ok(_) because we inserted a valid proposer slashing
    assert!(result.is_ok());
}

#[tokio::test]
async fn invalid_proposer_slashing_proposals_identical() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut proposer_slashing = harness.make_proposer_slashing(1);
    proposer_slashing.signed_header_1.message = proposer_slashing.signed_header_2.message.clone();

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting ProposalsIdentical because we the two headers are identical
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposalsIdentical
        })
    );
}

#[tokio::test]
async fn invalid_proposer_slashing_proposer_unknown() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let mut proposer_slashing = harness.make_proposer_slashing(1);
    proposer_slashing.signed_header_1.message.proposer_index = 3_141_592;
    proposer_slashing.signed_header_2.message.proposer_index = 3_141_592;

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting ProposerUnknown because validator_index is unknown
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposerUnknown(3_141_592)
        })
    );
}

#[tokio::test]
async fn invalid_proposer_slashing_duplicate_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let proposer_slashing = harness.make_proposer_slashing(1);
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result_1 = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing.clone()],
        VerifySignatures::False,
        &mut ctxt,
        &spec,
    );
    assert!(result_1.is_ok());

    let result_2 = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::False,
        &mut ctxt,
        &spec,
    );
    // Expecting ProposerNotSlashable because we've already slashed the validator
    assert_eq!(
        result_2,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposerNotSlashable(1)
        })
    );
}

#[tokio::test]
async fn invalid_bad_proposal_1_signature() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut proposer_slashing = harness.make_proposer_slashing(1);
    proposer_slashing.signed_header_1.signature = Signature::empty();
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting BadProposal1Signature because signature of proposal 1 is invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::BadProposal1Signature
        })
    );
}

#[tokio::test]
async fn invalid_bad_proposal_2_signature() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut proposer_slashing = harness.make_proposer_slashing(1);
    proposer_slashing.signed_header_2.signature = Signature::empty();
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting BadProposal2Signature because signature of proposal 2 is invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::BadProposal2Signature
        })
    );
}

#[tokio::test]
async fn invalid_proposer_slashing_proposal_epoch_mismatch() {
    let spec = MainnetEthSpec::default_spec();
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let mut proposer_slashing = harness.make_proposer_slashing(1);
    proposer_slashing.signed_header_1.message.slot = Slot::new(0);
    proposer_slashing.signed_header_2.message.slot = Slot::new(128);
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_proposer_slashings(
        &mut state,
        &[proposer_slashing],
        VerifySignatures::False,
        &mut ctxt,
        &spec,
    );

    // Expecting ProposalEpochMismatch because the two epochs are different
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposalSlotMismatch(
                Slot::from(0_u64),
                Slot::from(128_u64)
            )
        })
    );
}

#[tokio::test]
async fn fork_spanning_exit() {
    let mut spec = MainnetEthSpec::default_spec();
    let slots_per_epoch = MainnetEthSpec::slots_per_epoch();

    spec.altair_fork_epoch = Some(Epoch::new(2));
    spec.bellatrix_fork_epoch = Some(Epoch::new(4));
    spec.shard_committee_period = 0;

    let harness = BeaconChainHarness::builder(MainnetEthSpec::default())
        .spec(spec.clone())
        .deterministic_keypairs(VALIDATOR_COUNT)
        .mock_execution_layer()
        .fresh_ephemeral_store()
        .build();

    harness.extend_to_slot(slots_per_epoch.into()).await;

    /*
     * Produce an exit *before* Altair.
     */

    let signed_exit = harness.make_voluntary_exit(0, Epoch::new(1));
    assert!(signed_exit.message.epoch < spec.altair_fork_epoch.unwrap());

    /*
     * Ensure the exit verifies before Altair.
     */

    let head = harness.chain.canonical_head.cached_head();
    let head_state = &head.snapshot.beacon_state;
    assert!(head_state.current_epoch() < spec.altair_fork_epoch.unwrap());
    verify_exit(
        head_state,
        None,
        &signed_exit,
        VerifySignatures::True,
        &spec,
    )
    .expect("phase0 exit verifies against phase0 state");

    /*
     * Ensure the exit verifies after Altair.
     */

    harness
        .extend_to_slot(spec.altair_fork_epoch.unwrap().start_slot(slots_per_epoch))
        .await;
    let head = harness.chain.canonical_head.cached_head();
    let head_state = &head.snapshot.beacon_state;
    assert!(head_state.current_epoch() >= spec.altair_fork_epoch.unwrap());
    assert!(head_state.current_epoch() < spec.bellatrix_fork_epoch.unwrap());
    verify_exit(
        head_state,
        None,
        &signed_exit,
        VerifySignatures::True,
        &spec,
    )
    .expect("phase0 exit verifies against altair state");

    /*
     * Ensure the exit no longer verifies after Bellatrix.
     */

    harness
        .extend_to_slot(
            spec.bellatrix_fork_epoch
                .unwrap()
                .start_slot(slots_per_epoch),
        )
        .await;
    let head = harness.chain.canonical_head.cached_head();
    let head_state = &head.snapshot.beacon_state;
    assert!(head_state.current_epoch() >= spec.bellatrix_fork_epoch.unwrap());
    verify_exit(
        head_state,
        None,
        &signed_exit,
        VerifySignatures::True,
        &spec,
    )
    .expect_err("phase0 exit does not verify against bellatrix state");
}

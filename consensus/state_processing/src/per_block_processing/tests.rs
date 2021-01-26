#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use types::test_utils::{
    AttestationTestTask, AttesterSlashingTestTask, DepositTestTask, ProposerSlashingTestTask,
};
use types::*;

pub const NUM_DEPOSITS: u64 = 1;
pub const VALIDATOR_COUNT: usize = 64;
pub const EPOCH_OFFSET: u64 = 4;
pub const NUM_ATTESTATIONS: u64 = 1;

type E = MainnetEthSpec;

#[test]
fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let (block, mut state) = builder.build(None, None);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_block_header_state_slot() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let (mut block, mut state) = builder.build(None, None);

    state.slot = Slot::new(133_713);
    block.message.slot = Slot::new(424_242);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::StateSlotMismatch
        })
    );
}

#[test]
fn invalid_parent_block_root() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let invalid_parent_root = Hash256::from([0xAA; 32]);
    let (block, mut state) = builder.build(None, Some(invalid_parent_root));

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ParentBlockRootMismatch {
                state: state.latest_block_header.canonical_root(),
                block: block.parent_root()
            }
        })
    );
}

#[test]
fn invalid_block_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let (block, mut state) = builder.build(None, None);

    // sign the block with a keypair that is not the expected proposer
    let keypair = Keypair::random();
    let block = block.message.sign(
        &keypair.sk,
        &state.fork,
        state.genesis_validators_root,
        &spec,
    );

    // process block with invalid block signature
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_randao_reveal_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);

    // sign randao reveal with random keypair
    let keypair = Keypair::random();
    let (block, mut state) = builder.build(Some(keypair.sk), None);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // should get a BadRandaoSignature error
    assert_eq!(result, Err(BlockProcessingError::RandaoSignatureInvalid));
}

#[test]
fn valid_4_deposits() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(4, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok because these are valid deposits.
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_deposit_count_too_big() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let big_deposit_count = NUM_DEPOSITS + 1;
    state.eth1_data.deposit_count = big_deposit_count;

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting DepositCountInvalid because we incremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: big_deposit_count as usize,
            found: 1
        })
    );
}

#[test]
fn invalid_deposit_count_too_small() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let small_deposit_count = NUM_DEPOSITS - 1;
    state.eth1_data.deposit_count = small_deposit_count;

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting DepositCountInvalid because we decremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: small_deposit_count as usize,
            found: 1
        })
    );
}

#[test]
fn invalid_deposit_bad_merkle_proof() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let bad_index = state.eth1_deposit_index as usize;

    // Manually offsetting deposit count and index to trigger bad merkle proof
    state.eth1_data.deposit_count += 1;
    state.eth1_deposit_index += 1;
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadMerkleProof because the proofs were created with different indices
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositInvalid {
            index: bad_index,
            reason: DepositInvalid::BadMerkleProof
        })
    );
}

#[test]
fn invalid_deposit_wrong_pubkey() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::BadPubKey;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though the public key provided does not correspond to the correct public key
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_wrong_sig() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::BadSig;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though the block signature does not correspond to the correct public key
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_invalid_pub_key() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::InvalidPubKey;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though we passed in invalid publickeybytes in the public key field of the deposit data.
    assert_eq!(result, Ok(()));
}

#[test]
fn valid_attestations() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::Valid;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) because these are valid attestations
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_attestation_no_committee_for_index() {
    let spec = MainnetEthSpec::default_spec();
    let slot = Epoch::new(EPOCH_OFFSET).start_slot(E::slots_per_epoch());
    let builder =
        get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT).insert_attestation(slot, 0, |_, _| true);
    let committee_index = builder.state.get_committee_count_at_slot(slot).unwrap();
    let (block, mut state) = builder
        .modify(|block| {
            block.body.attestations[0].data.index = committee_index;
        })
        .build(None, None);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting NoCommitee because we manually set the attestation's index to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadCommitteeIndex
        })
    );
}

#[test]
fn invalid_attestation_wrong_justified_checkpoint() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::WrongJustifiedCheckpoint;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting WrongJustifiedCheckpoint because we manually set the
    // source field of the AttestationData object to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::WrongJustifiedCheckpoint {
                state: Checkpoint {
                    epoch: Epoch::from(2 as u64),
                    root: Hash256::zero(),
                },
                attestation: Checkpoint {
                    epoch: Epoch::from(0_u64),
                    root: Hash256::zero(),
                },
                is_current: true,
            }
        })
    );
}

#[test]
fn invalid_attestation_bad_indexed_attestation_bad_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadIndexedAttestationBadSignature;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadIndexedAttestation(BadSignature) because we ommitted the aggregation bits in the attestation
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

#[test]
fn invalid_attestation_bad_aggregation_bitfield_len() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadAggregationBitfieldLen;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting InvalidBitfield because the size of the aggregation_bitfield is bigger than the commitee size.
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::InvalidBitfield
        ))
    );
}

#[test]
fn invalid_attestation_bad_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, 97); // minimal number of required validators for this test
    let test_task = AttestationTestTask::BadSignature;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_attestation_included_too_early() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::IncludedTooEarly;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting IncludedTooEarly because the shard included in the crosslink is bigger than expected
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::IncludedTooEarly {
                state: state.slot,
                delay: spec.min_attestation_inclusion_delay,
                attestation: block.message.body.attestations[0].data.slot,
            }
        })
    );
}

#[test]
fn invalid_attestation_included_too_late() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommittee
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::IncludedTooLate;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::IncludedTooLate {
                state: state.slot,
                attestation: block.message.body.attestations[0].data.slot,
            }
        })
    );
}

#[test]
fn invalid_attestation_target_epoch_slot_mismatch() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommittee
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::TargetEpochSlotMismatch;
    let (block, mut state) =
        builder.build_with_n_attestations(test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    let attestation = &block.message.body.attestations[0].data;
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::TargetEpochSlotMismatch {
                target_epoch: attestation.target.epoch,
                slot_epoch: attestation.slot.epoch(E::slots_per_epoch()),
            }
        })
    );
}

#[test]
fn valid_insert_attester_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::Valid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(test_task, num_attester_slashings, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) because attester slashing is valid
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_attester_slashing_not_slashable() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::NotSlashable;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(test_task, num_attester_slashings, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_attester_slashing_1_invalid() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::IndexedAttestation1Invalid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(test_task, num_attester_slashings, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_attester_slashing_2_invalid() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::IndexedAttestation2Invalid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(test_task, num_attester_slashings, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn valid_insert_proposer_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::Valid;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) because we inserted a valid proposer slashing
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_proposer_slashing_proposals_identical() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposalsIdentical;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_proposer_slashing_proposer_unknown() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposerUnknown;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_proposer_slashing_not_slashable() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposerNotSlashable;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    state.validators[0].slashed = true;
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ProposerNotSlashable because we've already slashed the validator
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposerNotSlashable(0)
        })
    );
}

#[test]
fn invalid_proposer_slashing_duplicate_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::Valid;
    let (mut block, mut state) =
        builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let slashing = block.message.body.proposer_slashings[0].clone();
    let slashed_proposer = slashing.signed_header_1.message.proposer_index;
    block
        .message
        .body
        .proposer_slashings
        .push(slashing)
        .expect("should push slashing");

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::NoVerification,
        &spec,
    );

    // Expecting ProposerNotSlashable for the 2nd slashing because the validator has been
    // slashed by the 1st slashing.
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 1,
            reason: ProposerSlashingInvalid::ProposerNotSlashable(slashed_proposer)
        })
    );
}

#[test]
fn invalid_bad_proposal_1_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::BadProposal1Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_bad_proposal_2_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::BadProposal2Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
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

#[test]
fn invalid_proposer_slashing_proposal_epoch_mismatch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EPOCH_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposalEpochMismatch;
    let (block, mut state) = builder.build_with_proposer_slashing(test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ProposalEpochMismatch because the two epochs are different
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposalSlotMismatch(
                Slot::from(0_u64),
                Slot::from(128 as u64)
            )
        })
    );
}

fn get_builder(
    spec: &ChainSpec,
    epoch_offset: u64,
    num_validators: usize,
) -> BlockProcessingBuilder<MainnetEthSpec> {
    // Set the state and block to be in the last slot of the `epoch_offset`th epoch.
    let last_slot_of_epoch = (MainnetEthSpec::genesis_epoch() + epoch_offset)
        .end_slot(MainnetEthSpec::slots_per_epoch());
    BlockProcessingBuilder::new(num_validators, last_slot_of_epoch, &spec).build_caches()
}

#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::test_utils::{
    AttestationTestTask, AttesterSlashingTestTask, DepositTestTask, ExitTestTask,
    ProposerSlashingTestTask,
};
use types::*;

pub const NUM_DEPOSITS: u64 = 1;
pub const VALIDATOR_COUNT: usize = 10;
pub const SLOT_OFFSET: u64 = 4;
pub const EXIT_SLOT_OFFSET: u64 = 2048;
pub const NUM_ATTESTATIONS: u64 = 1;

#[test]
fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let (block, mut state) = builder.build(None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let (mut block, mut state) = builder.build(None, None, &spec);

    state.slot = Slot::new(133_713);
    block.slot = Slot::new(424_242);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let invalid_parent_root = Hash256::from([0xAA; 32]);
    let (block, mut state) = builder.build(None, Some(invalid_parent_root), &spec);

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
                state: Hash256::from_slice(&state.latest_block_header.signed_root()),
                block: block.parent_root
            }
        })
    );
}

#[test]
fn invalid_block_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let (mut block, mut state) = builder.build(None, None, &spec);

    // sign the block with a keypair that is not the expected proposer
    let keypair = Keypair::random();
    let message = block.signed_root();
    let epoch = block.slot.epoch(MainnetEthSpec::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::BeaconProposer, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);

    // sign randao reveal with random keypair
    let keypair = Keypair::random();
    let (block, mut state) = builder.build(Some(keypair.sk), None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
fn valid_insert_3_exits() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 3;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let test_task = ExitTestTask::Valid;
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok because these are valid exits.
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_exit_validator_unknown() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::ValidatorUnknown;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Validator Unknwon because the exit index is incorrect
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::ValidatorUnknown(4242),
        })
    );
}

#[test]
fn invalid_exit_already_exited() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::AlreadyExited;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting AlreadyExited because we manually set the exit_epoch to be different than far_future_epoch.
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::AlreadyExited(0),
        })
    );
}

#[test]
fn invalid_exit_not_active() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::NotActive;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting NotActive because we manually set the activation_epoch to be in the future
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::NotActive(0),
        })
    );
}

#[test]
fn invalid_exit_already_initiated() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::AlreadyInitiated;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though we inserted the same exit twice
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_exit_future_epoch() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::FutureEpoch;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting FutureEpoch because we set the exit_epoch to be far_future_epoch
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::FutureEpoch {
                state: Epoch::from(2048 as u64),
                exit: spec.far_future_epoch
            }
        })
    );
}

#[test]
fn invalid_exit_too_young() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::Valid;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting TooYoung because validator has not been active for long enough when trying to exit
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::TooYoungToExit {
                current_epoch: Epoch::from(SLOT_OFFSET),
                earliest_exit_epoch: Epoch::from(2048 as u64)
            },
        })
    );
}

#[test]
fn invalid_exit_bad_signature() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::BadSignature;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Bad Signature because we signed with a different secret key than the correct one.
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::BadSignature,
        })
    );
}

#[test]
fn valid_attestations() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::Valid;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
fn invalid_attestation_parent_crosslink_start_epoch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadParentCrosslinkStartEpoch;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkEndEpoch because we manually set an invalid crosslink start epoch
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadParentCrosslinkStartEpoch
        })
    );
}

#[test]
fn invalid_attestation_parent_crosslink_end_epoch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadParentCrosslinkEndEpoch;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkEndEpoch because we manually set an invalid crosslink end epoch
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadParentCrosslinkEndEpoch
        })
    );
}

#[test]
fn invalid_attestation_parent_crosslink_hash() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadParentCrosslinkHash;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkHash because we manually set an invalid crosslink parent_root
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadParentCrosslinkHash
        })
    );
}

#[test]
fn invalid_attestation_no_committee_for_shard() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::NoCommiteeForShard;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting NoCommiteeForShard because we manually set the crosslink's shard to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::NoCommitteeForShard
        ))
    );
}

#[test]
fn invalid_attestation_wrong_justified_checkpoint() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::WrongJustifiedCheckpoint;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
                    epoch: Epoch::from(0 as u64),
                    root: Hash256::zero(),
                },
                is_current: true,
            }
        })
    );
}

#[test]
fn invalid_attestation_bad_target_too_low() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadTargetTooLow;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting EpochTooLow because we manually set the
    // target field of the AttestationData object to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::RelativeEpochError(RelativeEpochError::EpochTooLow {
                base: state.current_epoch(),
                other: Epoch::from(0 as u64),
            })
        ))
    );
}

#[test]
fn invalid_attestation_bad_target_too_high() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadTargetTooHigh;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting EpochTooHigh because we manually set the
    // target field of the AttestationData object to be invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::RelativeEpochError(RelativeEpochError::EpochTooHigh {
                base: state.current_epoch(),
                other: Epoch::from(10 as u64),
            })
        ))
    );
}

#[test]
fn invalid_attestation_bad_crosslink_data_root() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadParentCrosslinkDataRoot;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ShardBlockRootNotZero because we manually set the
    // data_root of the cross link to be non zero

    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::ShardBlockRootNotZero,
        })
    );
}

#[test]
fn invalid_attestation_bad_indexed_attestation_bad_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, 33); // minmium number of validators required for this test
    let test_task = AttestationTestTask::BadIndexedAttestationBadSignature;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
fn invalid_attestation_custody_bitfield_not_subset() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, 33); // minmium number of validators required for this test
    let test_task = AttestationTestTask::CustodyBitfieldNotSubset;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting CustodyBitfieldNotSubset because we set custody_bit to true without setting the aggregation bits.
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::CustodyBitfieldNotSubset
        })
    );
}

#[test]
fn invalid_attestation_custody_bitfield_has_set_bits() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, 33); // minmium number of validators required for this test
    let test_task = AttestationTestTask::CustodyBitfieldHasSetBits;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting CustodyBitfieldHasSetBits because we set custody bits even though the custody_bit boolean is set to false
    assert_eq!(
        result,
        Err(BlockProcessingError::AttestationInvalid {
            index: 0,
            reason: AttestationInvalid::BadIndexedAttestation(
                IndexedAttestationInvalid::CustodyBitfieldHasSetBits
            )
        })
    );
}

#[test]
fn invalid_attestation_bad_custody_bitfield_len() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadCustodyBitfieldLen;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting InvalidBitfield because the size of the custody_bitfield is bigger than the commitee size.
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::InvalidBitfield
        ))
    );
}

#[test]
fn invalid_attestation_bad_aggregation_bitfield_len() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadAggregationBitfieldLen;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, 97); // minimal number of required validators for this test
    let test_task = AttestationTestTask::BadSignature;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::IncludedTooEarly;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
                state: Slot::from(319 as u64),
                delay: spec.min_attestation_inclusion_delay,
                attestation: Slot::from(319 as u64)
            }
        })
    );
}

#[test]
fn invalid_attestation_included_too_late() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommitteeForShard
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::IncludedTooLate;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting IncludedTooLate because the shard included in the crosslink is bigger than expected
    assert!(
        result
            == Err(BlockProcessingError::BeaconStateError(
                BeaconStateError::NoCommitteeForShard
            ))
            || result
                == Err(BlockProcessingError::AttestationInvalid {
                    index: 0,
                    reason: AttestationInvalid::IncludedTooLate {
                        state: state.slot,
                        attestation: Slot::from(254 as u64),
                    }
                })
    );
}

#[test]
fn invalid_attestation_bad_target_epoch() {
    let spec = MainnetEthSpec::default_spec();
    // note to maintainer: might need to increase validator count if we get NoCommitteeForShard
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadTargetEpoch;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadTargetEpoch because the target epoch is bigger by one than the epoch expected
    assert!(
        result
            == Err(BlockProcessingError::BeaconStateError(
                BeaconStateError::NoCommitteeForShard
            ))
            || result
                == Err(BlockProcessingError::AttestationInvalid {
                    index: 0,
                    reason: AttestationInvalid::BadTargetEpoch
                })
    );
}

#[test]
fn invalid_attestation_bad_shard() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttestationTestTask::BadShard;
    let (block, mut state) =
        builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadShard or NoCommitteeForShard because the shard number is higher than ShardCount
    assert!(
        result
            == Err(BlockProcessingError::AttestationInvalid {
                index: 0,
                reason: AttestationInvalid::BadShard
            })
            || result
                == Err(BlockProcessingError::BeaconStateError(
                    BeaconStateError::NoCommitteeForShard
                ))
    );
}

#[test]
fn valid_insert_attester_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::Valid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(&test_task, num_attester_slashings, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::NotSlashable;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(&test_task, num_attester_slashings, None, None, &spec);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::IndexedAttestation1Invalid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(&test_task, num_attester_slashings, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting IndexedAttestation1Invalid or IndexedAttestationInvalid because Attestation1 has CustodyBitfield bits set.
    assert!(
        result
            == Err(BlockProcessingError::IndexedAttestationInvalid {
                index: 0,
                reason: IndexedAttestationInvalid::CustodyBitfieldHasSetBits
            })
            || result
                == Err(BlockProcessingError::AttesterSlashingInvalid {
                    index: 0,
                    reason: AttesterSlashingInvalid::IndexedAttestation1Invalid(
                        BlockOperationError::Invalid(
                            IndexedAttestationInvalid::CustodyBitfieldHasSetBits
                        )
                    )
                })
    );
}

#[test]
fn invalid_attester_slashing_2_invalid() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = AttesterSlashingTestTask::IndexedAttestation2Invalid;
    let num_attester_slashings = 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(&test_task, num_attester_slashings, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting IndexedAttestation2Invalid or IndexedAttestationInvalid because Attestation2 has CustodyBitfield bits set.
    assert!(
        result
            == Err(BlockProcessingError::IndexedAttestationInvalid {
                index: 1,
                reason: IndexedAttestationInvalid::CustodyBitfieldHasSetBits
            })
            || result
                == Err(BlockProcessingError::AttesterSlashingInvalid {
                    index: 1,
                    reason: AttesterSlashingInvalid::IndexedAttestation2Invalid(
                        BlockOperationError::Invalid(
                            IndexedAttestationInvalid::CustodyBitfieldHasSetBits
                        )
                    )
                })
    );
}

#[test]
fn valid_insert_proposer_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::Valid;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposalsIdentical;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposerUnknown;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposerNotSlashable;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
fn invalid_bad_proposal_1_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::BadProposal1Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::BadProposal2Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = ProposerSlashingTestTask::ProposalEpochMismatch;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

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
            reason: ProposerSlashingInvalid::ProposalEpochMismatch(
                Slot::from(0 as u64),
                Slot::from(128 as u64)
            )
        })
    );
}

fn get_builder(
    spec: &ChainSpec,
    slot_offset: u64,
    num_validators: usize,
) -> (BlockProcessingBuilder<MainnetEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(num_validators, &spec);

    // Set the state and block to be in the last slot of the `slot_offset`th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + slot_offset).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}

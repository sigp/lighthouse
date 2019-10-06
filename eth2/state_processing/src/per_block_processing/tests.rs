#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::test_utils::AttesterSlashingTestTask;
use types::*;

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);

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
fn valid_insert_attester_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
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
fn valid_insert_max_attester_slashings_plus_one() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttesterSlashingTestTask::Valid;
    let num_attester_slashings = <MainnetEthSpec as EthSpec>::MaxAttesterSlashings::to_u64() + 1;
    let (block, mut state) =
        builder.build_with_attester_slashing(&test_task, num_attester_slashings, None, None, &spec);

    // Expecting Ok(()) because attester slashings are valid
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
fn invalid_attester_slashing_not_slashable() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);
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
    let builder = get_builder(&spec);
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

fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder<MainnetEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + 4).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}

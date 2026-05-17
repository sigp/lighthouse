#![cfg(all(test, not(feature = "fake_crypto"), not(debug_assertions)))]

use crate::per_block_processing::errors::{
    AttestationInvalid, AttesterSlashingInvalid, BlockOperationError, BlockProcessingError,
    DepositInvalid, HeaderInvalid, IndexedAttestationInvalid, IntoWithIndex,
    ProposerSlashingInvalid,
};
use crate::{BlockReplayError, BlockReplayer, per_block_processing};
use crate::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
    per_block_processing::process_operations,
};
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use bls::{AggregateSignature, Keypair, PublicKeyBytes, Signature, SignatureBytes};
use ssz_types::Bitfield;
use ssz_types::VariableList;
use std::sync::{Arc, LazyLock};
use test_utils::generate_deterministic_keypairs;
use types::*;

pub const MAX_VALIDATOR_COUNT: usize = 97;
pub const NUM_DEPOSITS: u64 = 1;
pub const VALIDATOR_COUNT: usize = 64;
pub const EPOCH_OFFSET: u64 = 4;
pub const NUM_ATTESTATIONS: u64 = 1;

// When set to true, cache any states fetched from the db.
pub const CACHE_STATE_IN_TESTS: bool = true;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(MAX_VALIDATOR_COUNT));

async fn get_harness<E: EthSpec>(
    epoch_offset: u64,
    num_validators: usize,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    get_harness_at_fork::<E>(epoch_offset, num_validators, ForkName::Electra).await
}

async fn get_gloas_harness<E: EthSpec>(
    epoch_offset: u64,
    num_validators: usize,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    get_harness_at_fork::<E>(epoch_offset, num_validators, ForkName::Gloas).await
}

async fn get_harness_at_fork<E: EthSpec>(
    epoch_offset: u64,
    num_validators: usize,
    fork_name: ForkName,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    // Set the state and block to be in the last slot of the `epoch_offset`th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + epoch_offset).end_slot(E::slots_per_epoch());
    let spec = Arc::new(fork_name.make_genesis_spec(E::default_spec()));
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(spec.clone())
        .keypairs(KEYPAIRS[0..num_validators].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    let state = harness.get_current_state();
    if last_slot_of_epoch > Slot::new(0) {
        harness
            .add_attested_blocks_at_slots(
                state,
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

fn builder_withdrawal_credentials(spec: &ChainSpec) -> Hash256 {
    let mut credentials = [0u8; 32];
    credentials[0] = spec.builder_withdrawal_prefix_byte;
    Hash256::from_slice(&credentials)
}

fn make_deposit_request(
    keypair: &Keypair,
    withdrawal_credentials: Hash256,
    amount: u64,
    spec: &ChainSpec,
    index: u64,
) -> DepositRequest {
    let mut deposit_data = DepositData {
        pubkey: keypair.pk.compress(),
        withdrawal_credentials,
        amount,
        signature: SignatureBytes::empty(),
    };
    deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);

    DepositRequest {
        pubkey: deposit_data.pubkey,
        withdrawal_credentials: deposit_data.withdrawal_credentials,
        amount: deposit_data.amount,
        signature: deposit_data.signature,
        index,
    }
}

fn find_builder_index<E: EthSpec>(
    state: &BeaconState<E>,
    pubkey: &PublicKeyBytes,
) -> Option<usize> {
    state
        .builders()
        .unwrap()
        .iter()
        .position(|builder| builder.pubkey == *pubkey)
}

#[tokio::test]
async fn valid_block_ok() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let state = harness.get_current_state();

    let slot = state.slot();
    let ((block, _), mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &block,
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        None,
        &spec,
    );

    assert!(result.is_ok());
}

#[tokio::test]
async fn invalid_block_header_state_slot() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let state = harness.get_current_state();
    let slot = state.slot() + Slot::new(1);

    let ((signed_block, _), mut state) = harness.make_block_return_pre_state(state, slot).await;
    let (mut block, signature) = (*signed_block).clone().deconstruct();
    *block.slot_mut() = slot + Slot::new(1);

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, signature),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        None,
        &spec,
    );

    assert!(matches!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::StateSlotMismatch,
        })
    ));
}

#[tokio::test]
async fn invalid_parent_block_root() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let state = harness.get_current_state();
    let slot = state.slot();

    let ((signed_block, _), mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;
    let (mut block, signature) = (*signed_block).clone().deconstruct();
    *block.parent_root_mut() = Hash256::from([0xAA; 32]);

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, signature),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        None,
        &spec,
    );

    assert!(matches!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ParentBlockRootMismatch { .. },
        })
    ));
}

#[tokio::test]
async fn invalid_block_signature() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let state = harness.get_current_state();
    let slot = state.slot();
    let ((signed_block, _), mut state) = harness
        .make_block_return_pre_state(state, slot + Slot::new(1))
        .await;
    let (block, _) = (*signed_block).clone().deconstruct();

    let mut ctxt = ConsensusContext::new(block.slot());
    let result = per_block_processing(
        &mut state,
        &SignedBeaconBlock::from_block(block, Signature::empty()),
        BlockSignatureStrategy::VerifyIndividual,
        VerifyBlockRoot::True,
        &mut ctxt,
        None,
        &spec,
    );

    assert!(matches!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ProposalSignatureInvalid,
        })
    ));
}

#[tokio::test]
async fn invalid_randao_reveal_signature() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let state = harness.get_current_state();
    let slot = state.slot();

    let ((signed_block, _), mut state) = harness
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
        None,
        &spec,
    );

    // should get a BadRandaoSignature error
    assert_eq!(result, Err(BlockProcessingError::RandaoSignatureInvalid));
}

#[tokio::test]
async fn valid_4_deposits() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 4, None, None);
    let deposits = VariableList::try_from(deposits).unwrap();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::try_from(deposits).unwrap();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::try_from(deposits).unwrap();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) = harness.make_deposits(&mut state, 1, None, None);
    let deposits = VariableList::try_from(deposits).unwrap();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) =
        harness.make_deposits(&mut state, 1, None, Some(SignatureBytes::empty()));
    let deposits = VariableList::try_from(deposits).unwrap();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, state) =
        harness.make_deposits(&mut state, 1, Some(PublicKeyBytes::empty()), None);
    let deposits = VariableList::try_from(deposits).unwrap();

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
async fn deposit_signature_batch_returns_true_for_valid_and_false_for_invalid() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (mut deposits, _) = harness.make_deposits(&mut state, 10, None, None);
    deposits[1].data.signature = SignatureBytes::empty();
    deposits[8].data.pubkey = PublicKeyBytes::empty();

    let result = per_block_processing::is_valid_deposit_signature_batch(
        deposits.into_iter().map(|deposit| deposit.data).collect(),
        &spec,
    );

    assert_eq!(result.len(), 10);
    assert_eq!(result[1], false);
    assert_eq!(result[8], false);
    assert!(
        result
            .iter()
            .enumerate()
            .all(|(index, is_valid)| matches!(index, 1 | 8) || *is_valid)
    );
}

#[tokio::test]
async fn deposit_signature_batch_returns_true_for_all_valid_signatures() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (deposits, _) = harness.make_deposits(&mut state, 10, None, None);

    let result = per_block_processing::is_valid_deposit_signature_batch(
        deposits.into_iter().map(|deposit| deposit.data).collect(),
        &spec,
    );

    assert_eq!(result, vec![true; 10]);
}

#[tokio::test]
async fn deposit_signature_batch_falls_back_to_individual_verification() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let (mut deposits, _) = harness.make_deposits(&mut state, 10, None, None);
    let wrong_signature = deposits[4].data.signature.clone();
    deposits[3].data.signature = wrong_signature;

    let result = per_block_processing::is_valid_deposit_signature_batch(
        deposits.into_iter().map(|deposit| deposit.data).collect(),
        &spec,
    );

    assert_eq!(result.len(), 10);
    assert_eq!(result[3], false);
    assert!(
        result
            .iter()
            .enumerate()
            .all(|(index, is_valid)| index == 3 || *is_valid)
    );
}

#[tokio::test]
async fn process_deposit_requests_post_gloas_batches_new_builder_signature_verification() {
    let harness = get_gloas_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let existing_builder_keypair = &KEYPAIRS[VALIDATOR_COUNT];
    let existing_builder_credentials = builder_withdrawal_credentials(&spec);
    let existing_builder_amount = 11;
    let slot = state.slot();
    state
        .add_builder_to_registry(
            existing_builder_keypair.pk.compress(),
            existing_builder_credentials,
            existing_builder_amount,
            slot,
            &spec,
        )
        .unwrap();

    let valid_builder_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 1],
        builder_withdrawal_credentials(&spec),
        13,
        &spec,
        0,
    );

    let mut invalid_builder_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 2],
        builder_withdrawal_credentials(&spec),
        17,
        &spec,
        1,
    );
    invalid_builder_request.signature = SignatureBytes::empty();

    let mut existing_builder_top_up = make_deposit_request(
        existing_builder_keypair,
        existing_builder_credentials,
        19,
        &spec,
        2,
    );
    existing_builder_top_up.signature = SignatureBytes::empty();

    let mut pending_validator_request =
        make_deposit_request(&KEYPAIRS[VALIDATOR_COUNT + 3], Hash256::ZERO, 23, &spec, 3);
    pending_validator_request.signature = SignatureBytes::empty();

    process_operations::process_deposit_requests_post_gloas(
        &mut state,
        &[
            valid_builder_request.clone(),
            invalid_builder_request.clone(),
            existing_builder_top_up.clone(),
            pending_validator_request.clone(),
        ],
        None,
        &spec,
    )
    .unwrap();

    let valid_builder_index = find_builder_index(&state, &valid_builder_request.pubkey);
    assert!(valid_builder_index.is_some());

    let invalid_builder_index = find_builder_index(&state, &invalid_builder_request.pubkey);
    assert!(invalid_builder_index.is_none());

    let existing_builder_index =
        find_builder_index(&state, &existing_builder_top_up.pubkey).unwrap();
    let existing_builder = state
        .builders()
        .unwrap()
        .get(existing_builder_index)
        .unwrap();
    assert_eq!(
        existing_builder.balance,
        existing_builder_amount + existing_builder_top_up.amount
    );

    let pending_deposits = state.pending_deposits().unwrap();
    assert_eq!(pending_deposits.len(), 1);
    assert_eq!(
        pending_deposits.get(0).unwrap().pubkey,
        pending_validator_request.pubkey
    );
    assert_eq!(
        pending_deposits.get(0).unwrap().amount,
        pending_validator_request.amount
    );
}

#[tokio::test]
async fn process_deposit_requests_post_gloas_preserves_existing_builder_path() {
    let harness = get_gloas_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let pubkey = KEYPAIRS[VALIDATOR_COUNT + 4].pk.compress();
    let withdrawal_credentials = builder_withdrawal_credentials(&spec);

    let first_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 4],
        withdrawal_credentials,
        29,
        &spec,
        0,
    );
    let mut second_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 4],
        withdrawal_credentials,
        31,
        &spec,
        1,
    );
    second_request.signature = SignatureBytes::empty();

    process_operations::process_deposit_requests_post_gloas(
        &mut state,
        &[first_request.clone(), second_request.clone()],
        None,
        &spec,
    )
    .unwrap();

    let builder_index = find_builder_index(&state, &pubkey).unwrap();
    let builder = state.builders().unwrap().get(builder_index).unwrap();
    assert_eq!(
        builder.balance,
        first_request.amount + second_request.amount
    );
}

#[tokio::test]
async fn process_deposit_requests_post_gloas_preserves_pending_validator_path() {
    let harness = get_gloas_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let pending_validator_request =
        make_deposit_request(&KEYPAIRS[VALIDATOR_COUNT + 5], Hash256::ZERO, 37, &spec, 0);
    let builder_prefixed_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 5],
        builder_withdrawal_credentials(&spec),
        41,
        &spec,
        1,
    );

    process_operations::process_deposit_requests_post_gloas(
        &mut state,
        &[
            pending_validator_request.clone(),
            builder_prefixed_request.clone(),
        ],
        None,
        &spec,
    )
    .unwrap();

    assert!(find_builder_index(&state, &pending_validator_request.pubkey).is_none());

    let pending_deposits = state.pending_deposits().unwrap();
    assert_eq!(pending_deposits.len(), 2);
    assert_eq!(
        pending_deposits.get(0).unwrap().pubkey,
        pending_validator_request.pubkey
    );
    assert_eq!(
        pending_deposits.get(1).unwrap().pubkey,
        builder_prefixed_request.pubkey
    );
}

#[tokio::test]
async fn process_deposit_requests_post_gloas_preserves_existing_builder_before_validator_path() {
    let harness = get_gloas_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let builder_prefixed_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 6],
        builder_withdrawal_credentials(&spec),
        43,
        &spec,
        0,
    );
    let validator_prefixed_request =
        make_deposit_request(&KEYPAIRS[VALIDATOR_COUNT + 6], Hash256::ZERO, 47, &spec, 1);

    process_operations::process_deposit_requests_post_gloas(
        &mut state,
        &[
            builder_prefixed_request.clone(),
            validator_prefixed_request.clone(),
        ],
        None,
        &spec,
    )
    .unwrap();

    let builder_index = find_builder_index(&state, &builder_prefixed_request.pubkey).unwrap();
    let builder = state.builders().unwrap().get(builder_index).unwrap();
    assert_eq!(
        builder.balance,
        builder_prefixed_request.amount + validator_prefixed_request.amount
    );
    assert!(state.pending_deposits().unwrap().is_empty());
}

#[tokio::test]
async fn process_deposit_requests_post_gloas_preserves_pre_state_pending_validator_path() {
    let harness = get_gloas_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
    let mut state = harness.get_current_state();

    let pending_validator_request =
        make_deposit_request(&KEYPAIRS[VALIDATOR_COUNT + 7], Hash256::ZERO, 53, &spec, 0);
    let slot = state.slot();
    state
        .pending_deposits_mut()
        .unwrap()
        .push(PendingDeposit {
            pubkey: pending_validator_request.pubkey,
            withdrawal_credentials: pending_validator_request.withdrawal_credentials,
            amount: pending_validator_request.amount,
            signature: pending_validator_request.signature.clone(),
            slot,
        })
        .unwrap();

    let builder_prefixed_request = make_deposit_request(
        &KEYPAIRS[VALIDATOR_COUNT + 7],
        builder_withdrawal_credentials(&spec),
        59,
        &spec,
        1,
    );

    process_operations::process_deposit_requests_post_gloas(
        &mut state,
        &[builder_prefixed_request.clone()],
        None,
        &spec,
    )
    .unwrap();

    assert!(find_builder_index(&state, &builder_prefixed_request.pubkey).is_none());

    let pending_deposits = state.pending_deposits().unwrap();
    assert_eq!(pending_deposits.len(), 2);
    assert_eq!(
        pending_deposits.get(0).unwrap().pubkey,
        pending_validator_request.pubkey
    );
    assert_eq!(
        pending_deposits.get(1).unwrap().pubkey,
        builder_prefixed_request.pubkey
    );
}

#[tokio::test]
async fn invalid_attestation_no_committee_for_index() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .data_mut()
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    let old_justified_checkpoint = head_block
        .body()
        .attestations()
        .next()
        .unwrap()
        .data()
        .source;
    let mut new_justified_checkpoint = old_justified_checkpoint;
    new_justified_checkpoint.epoch += Epoch::new(1);
    head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .data_mut()
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
                state: Box::new(old_justified_checkpoint),
                attestation: Box::new(new_justified_checkpoint),
                is_current: true,
            }
        })
    );
}

#[tokio::test]
async fn invalid_attestation_bad_aggregation_bitfield_len() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    // Use Electra method since harness runs at Electra fork
    *head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .aggregation_bits_electra_mut()
        .unwrap() = Bitfield::with_capacity(spec.target_committee_size).unwrap();

    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attestations(
        &mut state,
        head_block.body(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // In Electra, setting wrong aggregation_bits capacity causes EmptyCommittee error
    // (validation order changed - committee check happens before bitfield check)
    assert_eq!(
        result,
        Err(BlockProcessingError::BeaconStateError(
            BeaconStateError::EmptyCommittee
        ))
    );
}

#[tokio::test]
async fn invalid_attestation_bad_signature() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, 97).await; // minimal number of required validators for this test
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    *head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .signature_mut() = AggregateSignature::empty();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    let new_attesation_slot = head_block.body().attestations().next().unwrap().data().slot
        + Slot::new(MainnetEthSpec::slots_per_epoch());
    head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .data_mut()
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

// Note: `invalid_attestation_included_too_late` test removed.
// The `IncludedTooLate` check was removed in Deneb (EIP7045), so this test is no longer
// applicable when running with Electra spec (which the harness uses by default).

#[tokio::test]
async fn invalid_attestation_target_epoch_slot_mismatch() {
    // note to maintainer: might need to increase validator count if we get NoCommittee
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut state = harness.get_current_state();
    let mut head_block = harness
        .chain
        .head_beacon_block()
        .as_ref()
        .clone()
        .deconstruct()
        .0;
    head_block
        .to_mut()
        .body_mut()
        .attestations_mut()
        .next()
        .unwrap()
        .data_mut()
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let attester_slashing = harness.make_attester_slashing(vec![1, 2]);

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        [attester_slashing.to_ref()].into_iter(),
        VerifySignatures::True,
        &mut ctxt,
        &spec,
    );

    // Expecting Ok(()) because attester slashing is valid
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn invalid_attester_slashing_not_slashable() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    match &mut attester_slashing {
        AttesterSlashing::Base(attester_slashing) => {
            attester_slashing.attestation_1 = attester_slashing.attestation_2.clone();
        }
        AttesterSlashing::Electra(attester_slashing) => {
            attester_slashing.attestation_1 = attester_slashing.attestation_2.clone();
        }
    }

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        [attester_slashing.to_ref()].into_iter(),
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    match &mut attester_slashing {
        AttesterSlashing::Base(attester_slashing) => {
            attester_slashing.attestation_1.attesting_indices =
                VariableList::try_from(vec![2, 1]).unwrap();
        }
        AttesterSlashing::Electra(attester_slashing) => {
            attester_slashing.attestation_1.attesting_indices =
                VariableList::try_from(vec![2, 1]).unwrap();
        }
    }

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        [attester_slashing.to_ref()].into_iter(),
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let mut attester_slashing = harness.make_attester_slashing(vec![1, 2]);
    match &mut attester_slashing {
        AttesterSlashing::Base(attester_slashing) => {
            attester_slashing.attestation_2.attesting_indices =
                VariableList::try_from(vec![2, 1]).unwrap();
        }
        AttesterSlashing::Electra(attester_slashing) => {
            attester_slashing.attestation_2.attesting_indices =
                VariableList::try_from(vec![2, 1]).unwrap();
        }
    }

    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result = process_operations::process_attester_slashings(
        &mut state,
        [attester_slashing.to_ref()].into_iter(),
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();

    let proposer_slashing = harness.make_proposer_slashing(1);
    let mut state = harness.get_current_state();
    let mut ctxt = ConsensusContext::new(state.slot());
    let result_1 = process_operations::process_proposer_slashings(
        &mut state,
        std::slice::from_ref(&proposer_slashing),
        VerifySignatures::False,
        &mut ctxt,
        &spec,
    );
    assert!(result_1.is_ok());

    let result_2 = process_operations::process_proposer_slashings(
        &mut state,
        std::slice::from_ref(&proposer_slashing),
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
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
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;
    let spec = harness.spec.clone();
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

/// Check that the block replayer does not consume state roots unnecessarily.
#[tokio::test]
async fn block_replayer_peeking_state_roots() {
    let harness = get_harness::<MainnetEthSpec>(EPOCH_OFFSET, VALIDATOR_COUNT).await;

    let target_state = harness.get_current_state();
    let target_block_root = harness.head_block_root();
    let target_block = harness
        .chain
        .get_blinded_block(&target_block_root)
        .unwrap()
        .unwrap();

    let parent_block_root = target_block.parent_root();
    let parent_block = harness
        .chain
        .get_blinded_block(&parent_block_root)
        .unwrap()
        .unwrap();
    // Cache the state to make CI go brr.
    let parent_state = harness
        .chain
        .get_state(&parent_block.state_root(), Some(parent_block.slot()), true)
        .unwrap()
        .unwrap();

    // Omit the state root for `target_state` but provide a dummy state root at the *next* slot.
    // If the block replayer is peeking at the state roots rather than consuming them, then the
    // dummy state should still be there after block replay completes.
    let dummy_state_root = Hash256::repeat_byte(0xff);
    let dummy_slot = target_state.slot() + 1;
    let state_root_iter = vec![Ok::<_, BlockReplayError>((dummy_state_root, dummy_slot))];
    let block_replayer = BlockReplayer::new(parent_state, &harness.chain.spec)
        .state_root_iter(state_root_iter.into_iter())
        .no_signature_verification()
        .apply_blocks(vec![target_block], None)
        .unwrap();

    assert_eq!(
        block_replayer
            .state_root_iter
            .unwrap()
            .next()
            .unwrap()
            .unwrap(),
        (dummy_state_root, dummy_slot)
    );
}

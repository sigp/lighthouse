use super::*;
use crate::{
    genesis::{PqGenesisValidator, initialize_pq_genesis},
    per_block_processing::{
        apply_parent_execution_payload_pq,
        errors::BlockProcessingError,
        process_operations::{process_builder_deposit_requests, process_deposit_requests},
        process_parent_execution_payload,
    },
    per_epoch_processing::{
        process_epoch,
        single_pass::{SinglePassConfig, process_epoch_single_pass},
    },
    per_slot_processing,
};
use bls::{PublicKeyBytes, SignatureBytes};
use tree_hash::TreeHash;

type E = MinimalEthSpec;

fn genesis(validator_count: usize) -> (BeaconState<E>, ChainSpec) {
    let spec = ForkName::Pq.make_genesis_spec(E::default_spec());
    let validators = (0..validator_count)
        .map(|index| {
            let mut pubkey = [0; 32];
            pubkey[..8].copy_from_slice(&(index as u64).to_le_bytes());
            PqGenesisValidator {
                pubkey: pubkey.into(),
                vrf_root: Hash256::ZERO,
                withdrawal_credentials: Hash256::ZERO,
                balance: spec.max_effective_balance,
            }
        })
        .collect();
    let state = initialize_pq_genesis(Hash256::repeat_byte(0x42), 1234, validators, None, &spec)
        .expect("PQ genesis");
    (state, spec)
}

fn deposit(pubkey: PublicKeyBytes, amount: u64) -> DepositRequest {
    DepositRequest {
        pubkey,
        amount,
        withdrawal_credentials: Hash256::repeat_byte(0x01),
        signature: SignatureBytes::deserialize(&[0xf0; 96]).unwrap(),
        index: 42,
    }
}

#[test]
fn pq_pending_deposits_consume_churn_and_legacy_exits_immediately() {
    let (mut state, spec) = genesis(8);
    let normal_key = XmssPublicKey::from([0xd1; 32]);
    let normal_pubkey = encode_deposit_pubkey(normal_key).unwrap();
    let legacy_pubkey = PublicKeyBytes::deserialize(&[0x90; 48]).unwrap();
    let legacy_key = compute_deposit_pubkey(&legacy_pubkey);
    let top_up_key = state.get_validator(0).unwrap().pubkey;
    let top_up = deposit(
        encode_deposit_pubkey(top_up_key).unwrap(),
        spec.effective_balance_increment,
    );
    let normal = deposit(normal_pubkey, spec.min_activation_balance);
    let legacy = deposit(legacy_pubkey, spec.min_activation_balance * 12);
    let encoded_legacy = deposit(
        encode_deposit_pubkey(legacy_key).unwrap(),
        spec.effective_balance_increment,
    );
    let too_large = deposit(
        encode_deposit_pubkey([0x77; 32].into()).unwrap(),
        spec.min_activation_balance * 12,
    );

    process_deposit_requests(
        &mut state,
        &[top_up, normal, legacy, encoded_legacy, too_large],
        &spec,
    )
    .unwrap();
    let churn = state.get_activation_exit_churn_limit(&spec).unwrap();
    let validator_count = state.validators().len();
    crate::state_advance::complete_state_advance(
        &mut state,
        None,
        Slot::new(E::slots_per_epoch() - 1),
        None,
        &spec,
    )
    .unwrap();
    process_epoch(&mut state, &spec).unwrap();

    assert_eq!(state.validators().len(), validator_count + 2);
    assert_eq!(
        state.get_validator_index(&normal_key).unwrap(),
        Some(validator_count)
    );
    assert_eq!(
        state.get_validator_index(&legacy_key).unwrap(),
        Some(validator_count + 1)
    );
    let normal = state.get_validator(validator_count).unwrap();
    assert_eq!(normal.vrf_root, Hash256::repeat_byte(0xf0));
    assert_eq!(normal.exit_epoch, spec.far_future_epoch);
    let legacy = state.get_validator(validator_count + 1).unwrap();
    assert_eq!(legacy.exit_epoch, state.current_epoch());
    assert_eq!(
        legacy.withdrawable_epoch,
        spec.min_validator_withdrawability_delay
    );
    assert_eq!(
        legacy.vrf_root,
        compute_deposit_vrf_root(&legacy_pubkey, &SignatureBytes::empty())
    );
    assert_eq!(
        state.get_balance(0).unwrap(),
        spec.max_effective_balance + spec.effective_balance_increment
    );
    assert_eq!(
        state.deposit_balance_to_consume().unwrap(),
        churn - spec.min_activation_balance - spec.effective_balance_increment
    );
    let queued = state.pending_deposits().unwrap();
    assert_eq!(queued.len(), 2);
    assert_eq!(
        queued.get(1).unwrap().pubkey,
        encode_deposit_pubkey(legacy_key).unwrap()
    );
    assert_eq!(state.deposit_requests_start_index().unwrap(), 0);
}

#[test]
fn pq_deposits_enforce_live_preregistration_and_finalization() {
    let (mut state, spec) = genesis(8);
    let key = XmssPublicKey::from([0xa0; 32]);
    let requests = ExecutionRequestsPq::<E> {
        deposits: ssz_types::ProgressiveVariableList::new(vec![deposit(
            encode_deposit_pubkey(key).unwrap(),
            spec.min_activation_balance,
        )])
        .unwrap(),
        ..Default::default()
    };
    let binding = ValidatorPreregistration {
        pubkey: key,
        withdrawal_credentials: Hash256::repeat_byte(0x02),
        vrf_root: Hash256::repeat_byte(0xf0),
        expiry_slot: Slot::new(8),
    };
    state
        .as_pq_mut()
        .unwrap()
        .validator_preregistrations
        .push(binding)
        .unwrap();
    *state.slot_mut() = Slot::new(1);
    let parent_hash = ExecutionBlockHash::from_root(Hash256::repeat_byte(0x6f));
    let parent_bid = state.latest_execution_payload_bid_gloas_mut().unwrap();
    parent_bid.block_hash = parent_hash;
    parent_bid.execution_requests_root = requests.tree_hash_root();
    let mut child = BeaconBlockPq::<E, FullPayload<E>>::empty(&spec);
    child.body.parent_execution_requests = requests.clone();

    let block = BeaconBlock::Pq(child.clone());
    assert_eq!(
        process_parent_execution_payload(&mut state, block.to_ref(), &spec),
        Err(BlockProcessingError::NonEmptyParentExecutionRequests),
    );

    child
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash = parent_hash;
    let block = BeaconBlock::Pq(child);
    process_parent_execution_payload(&mut state, block.to_ref(), &spec).unwrap();
    assert!(state.pending_deposits().unwrap().is_empty());
    let binding = state
        .as_pq_mut()
        .unwrap()
        .validator_preregistrations
        .get_mut(0)
        .unwrap();
    binding.withdrawal_credentials = Hash256::repeat_byte(0x01);
    binding.vrf_root = Hash256::repeat_byte(0xf1);
    apply_parent_execution_payload_pq(&mut state, &requests, &spec).unwrap();
    assert!(state.pending_deposits().unwrap().is_empty());
    state
        .as_pq_mut()
        .unwrap()
        .validator_preregistrations
        .get_mut(0)
        .unwrap()
        .vrf_root = Hash256::repeat_byte(0xf0);
    apply_parent_execution_payload_pq(&mut state, &requests, &spec).unwrap();
    assert!(state.as_pq().unwrap().validator_preregistrations.is_empty());
    assert_eq!(
        state.pending_deposits().unwrap().get(0).unwrap().slot,
        Slot::new(1)
    );
    process_epoch_single_pass(
        &mut state,
        &spec,
        SinglePassConfig {
            pending_deposits: true,
            ..SinglePassConfig::disable_all()
        },
    )
    .unwrap();
    assert_eq!(state.pending_deposits().unwrap().len(), 1);
    assert_eq!(state.get_validator_index(&key).unwrap(), None);

    let nonempty_stub = ExecutionRequestsPq::<E> {
        voluntary_exits: ssz_types::ProgressiveVariableList::new(vec![VoluntaryExitRequest {
            pubkey: key,
        }])
        .unwrap(),
        ..Default::default()
    };
    assert_eq!(
        apply_parent_execution_payload_pq(&mut state, &nonempty_stub, &spec),
        Err(BlockProcessingError::NonEmptyPqRequest("voluntary_exits"))
    );
}

#[test]
fn pq_builder_deposits_reuse_swept_index_and_exit_legacy_creations() {
    let (mut state, spec) = genesis(8);
    let key = [0xd2; 32].into();
    let mut credentials = Hash256::ZERO;
    credentials.0[0] = spec.builder_withdrawal_prefix_byte;
    let empty_builder = state
        .add_builder_to_registry(
            key,
            consts::gloas::PAYLOAD_BUILDER_VERSION,
            credentials,
            0,
            Slot::new(0),
            &spec,
        )
        .unwrap();
    state
        .builders_mut()
        .unwrap()
        .get_mut(empty_builder as usize)
        .unwrap()
        .withdrawable_epoch = Epoch::new(0);
    let legacy_pubkey = PublicKeyBytes::deserialize(&[0x88; 48]).unwrap();
    let request = BuilderDepositRequest {
        pubkey: legacy_pubkey,
        withdrawal_credentials: credentials,
        amount: spec.min_activation_balance,
        signature: SignatureBytes::empty(),
    };
    process_builder_deposit_requests(&mut state, &[request], &spec).unwrap();
    assert_eq!(state.builders().unwrap().len(), 1);
    let builder = state.get_builder(empty_builder).unwrap();
    assert_eq!(builder.pubkey, compute_deposit_pubkey(&legacy_pubkey));
    assert_eq!(
        builder.withdrawable_epoch,
        spec.min_builder_withdrawability_delay
    );
}

#[test]
fn pq_caps_committees_and_rotates_aggregation_window() {
    let (mut state, spec) = genesis(8);
    let state_pq = state.as_pq().unwrap();
    let width = E::slots_per_epoch() as usize;
    let genesis_window = state_pq.aggregation_committee_window.clone();
    assert!(
        genesis_window
            .iter()
            .take(width)
            .all(|committees| committees.is_empty())
    );
    assert!(
        genesis_window
            .iter()
            .skip(width)
            .all(|committees| !committees.is_empty())
    );

    for _ in 0..width {
        per_slot_processing::per_slot_processing(
            &mut state,
            None,
            crate::GloasVerificationContext::FullVerification,
            &spec,
        )
        .unwrap();
    }
    let state_pq = state.as_pq().unwrap();
    for (actual, expected) in state_pq
        .aggregation_committee_window
        .iter()
        .zip(genesis_window.iter().skip(width))
    {
        assert_eq!(actual, expected);
    }

    let (mut state, mut spec) = genesis(192);
    spec.target_committee_size = 1;
    state.drop_committee_cache(RelativeEpoch::Current).unwrap();
    state
        .build_committee_cache(RelativeEpoch::Current, &spec)
        .unwrap();
    let committees = state.get_beacon_committees_at_slot(Slot::new(0)).unwrap();
    assert_eq!(committees.len(), E::max_committees_per_slot_pq());
    let cache = state.committee_cache(RelativeEpoch::Current).unwrap();
    let aggregate = state
        .compute_aggregation_committees(Slot::new(0), cache, &spec)
        .unwrap();
    for (committee, aggregators) in committees.iter().zip(aggregate.iter()) {
        assert_eq!(aggregators.len(), 4);
        assert_eq!(
            aggregators
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            aggregators.len()
        );
        assert!(
            aggregators
                .iter()
                .all(|index| committee.committee.contains(&(*index as usize)))
        );
    }
}

#[test]
fn pq_head_flag_uses_attested_ancestor_across_skipped_slots() {
    use crate::common::{get_attestation_participation_flag_indices, get_latest_block_slot};
    use types::consts::altair::TIMELY_HEAD_FLAG_INDEX;

    let (mut state, spec) = genesis(8);
    *state.slot_mut() = Slot::new(7);
    let attested_root = Hash256::repeat_byte(0xa4);
    for slot in (3..=5).map(Slot::new) {
        state.set_block_root(slot, attested_root).unwrap();
    }
    let parent_slot = Slot::new(6);
    let vote_slot = Slot::new(5);
    state
        .execution_payload_availability_mut()
        .unwrap()
        .set(6, false)
        .unwrap();
    assert_eq!(
        get_latest_block_slot(&state, vote_slot, parent_slot).unwrap(),
        Slot::new(3)
    );
    let data = AttestationData {
        slot: vote_slot,
        index: 1,
        beacon_block_root: attested_root,
        source: state.current_justified_checkpoint(),
        target: Checkpoint {
            epoch: state.current_epoch(),
            root: *state
                .get_block_root_at_epoch(state.current_epoch())
                .unwrap(),
        },
    };
    let flags =
        get_attestation_participation_flag_indices(&state, &data, Some(parent_slot), 2, &spec)
            .unwrap();
    assert!(flags.contains(&TIMELY_HEAD_FLAG_INDEX));
}

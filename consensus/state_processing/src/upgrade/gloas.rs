use crate::builder_deposits_cache::{OnboardBuildersCache, is_valid_deposit_signature_cached};
use crate::per_block_processing::process_operations::is_pending_validator;
use bls::PublicKeyBytes;
use milhouse::{ProgressiveList, Vector};
use safe_arith::SafeArith;
use ssz_types::{BitVector, FixedVector};
use std::marker::PhantomData;
use std::{collections::HashMap, mem};
use tracing::debug;
use tree_hash::TreeHash;
use typenum::Unsigned;
use types::{
    Address, BeaconState, BeaconStateError as Error, BeaconStateGloas, Builder,
    BuilderPendingPayment, ChainSpec, EthSpec, ExecutionPayloadBid, ExecutionRequestsGloas, Fork,
    PendingDeposit, ProgressiveKzgCommitments,
    consts::gloas::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION},
    is_builder_withdrawal_credential,
};

/// Controls how builder deposit signatures are verified during `upgrade_to_gloas`.
///
/// The fork transition must check the signature of every builder deposit in the (unbounded)
/// `pending_deposits` queue. The spec recommends clients pre-verify these signatures and
/// cache the results (see the note in `specs/gloas/fork.md`) so that the fork transition
/// itself is fast.
pub enum GloasVerificationContext<'a> {
    /// Use the pre-computed builder deposit signature cache, falling back to inline
    /// verification on cache miss.
    CachedVerification(&'a OnboardBuildersCache),
    /// Verify each builder deposit signature inline.
    ///
    /// This can be significantly slower if there are many builder deposits to onboard at the
    /// fork boundary. This variant should be used for tests and other non-hot paths.
    FullVerification,
}

impl<'a> GloasVerificationContext<'a> {
    pub fn from_cache(cache: Option<&'a OnboardBuildersCache>) -> Self {
        match cache {
            Some(cache) => GloasVerificationContext::CachedVerification(cache),
            None => GloasVerificationContext::FullVerification,
        }
    }

    fn cache(&self) -> Option<&'a OnboardBuildersCache> {
        match self {
            GloasVerificationContext::CachedVerification(cache) => Some(cache),
            GloasVerificationContext::FullVerification => None,
        }
    }
}

/// Transform a `Fulu` state into a `Gloas` state.
pub fn upgrade_to_gloas<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    context: GloasVerificationContext<'_>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let post = upgrade_state_to_gloas(pre_state, context, spec)?;

    *pre_state = post;

    Ok(())
}

pub fn upgrade_state_to_gloas<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    context: GloasVerificationContext<'_>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_fulu_mut()?;
    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let mut post = BeaconState::Gloas(BeaconStateGloas {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.gloas_fork_version,
            epoch,
        },
        // History
        latest_block_header: pre.latest_block_header.clone(),
        block_roots: pre.block_roots.clone(),
        state_roots: pre.state_roots.clone(),
        historical_roots: mem::take(&mut pre.historical_roots),
        // Eth1
        eth1_data: pre.eth1_data.clone(),
        eth1_data_votes: mem::take(&mut pre.eth1_data_votes),
        eth1_deposit_index: pre.eth1_deposit_index,
        // Registry
        validators: ProgressiveList::try_from_iter(pre.validators.iter().cloned())?,
        balances: ProgressiveList::try_from_iter(pre.balances.iter().copied())?,
        // Randomness
        randao_mixes: pre.randao_mixes.clone(),
        // Slashings
        slashings: pre.slashings.clone(),
        // Participation
        previous_epoch_participation: ProgressiveList::try_from_iter(
            pre.previous_epoch_participation.iter().cloned(),
        )?,
        current_epoch_participation: ProgressiveList::try_from_iter(
            pre.current_epoch_participation.iter().cloned(),
        )?,
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores: ProgressiveList::try_from_iter(pre.inactivity_scores.iter().copied())?,
        // Sync committees
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        // Execution Bid
        latest_execution_payload_bid: ExecutionPayloadBid {
            parent_block_hash: pre.latest_execution_payload_header.parent_hash,
            parent_block_root: pre.latest_block_header.parent_root,
            block_hash: pre.latest_execution_payload_header.block_hash,
            prev_randao: pre.latest_execution_payload_header.prev_randao,
            fee_recipient: Address::ZERO,
            gas_limit: pre.latest_execution_payload_header.gas_limit,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot: pre.latest_block_header.slot,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: ProgressiveKzgCommitments::default(),
            execution_requests_root: ExecutionRequestsGloas::<E>::default().tree_hash_root(),
            _phantom: PhantomData,
        },
        // Capella
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // Electra
        deposit_requests_start_index: pre.deposit_requests_start_index,
        deposit_balance_to_consume: pre.deposit_balance_to_consume,
        exit_balance_to_consume: pre.exit_balance_to_consume,
        earliest_exit_epoch: pre.earliest_exit_epoch,
        consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
        pending_deposits: ProgressiveList::try_from_iter(pre.pending_deposits.iter().cloned())?,
        pending_partial_withdrawals: ProgressiveList::try_from_iter(
            pre.pending_partial_withdrawals.iter().cloned(),
        )?,
        pending_consolidations: ProgressiveList::try_from_iter(
            pre.pending_consolidations.iter().cloned(),
        )?,
        proposer_lookahead: mem::take(&mut pre.proposer_lookahead),
        // Gloas
        builders: ProgressiveList::default(),
        next_withdrawal_builder_index: 0,
        // All bits set to true per spec:
        // execution_payload_availability = [0b1 for _ in range(SLOTS_PER_HISTORICAL_ROOT)]
        execution_payload_availability: BitVector::from_bytes(
            vec![0xFFu8; E::SlotsPerHistoricalRoot::to_usize() / 8].into(),
        )
        .map_err(|_| Error::InvalidBitfield)?,
        builder_pending_payments: Vector::from_elem(BuilderPendingPayment::default())?,
        builder_pending_withdrawals: ProgressiveList::default(), // Empty list initially,
        latest_block_hash: pre.latest_execution_payload_header.block_hash,
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::from_elem(FixedVector::from_elem(0))?, // placeholder, will be initialized below
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        slashings_cache: mem::take(&mut pre.slashings_cache),
        epoch_cache: mem::take(&mut pre.epoch_cache),
    });
    // [New in Gloas:EIP7732]
    onboard_builders_from_pending_deposits(&mut post, context.cache(), spec)?;
    initialize_ptc_window(&mut post, spec)?;

    Ok(post)
}

/// Initialize the `ptc_window` field in the beacon state at fork transition.
///
/// The window contains:
/// - One epoch of empty entries (previous epoch)
/// - Computed PTC for the current epoch through `1 + MIN_SEED_LOOKAHEAD` epochs
fn initialize_ptc_window<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let slots_per_epoch = E::slots_per_epoch() as usize;

    let empty_previous_epoch = vec![FixedVector::<u64, E::PTCSize>::from_elem(0); slots_per_epoch];
    let mut ptcs = empty_previous_epoch;

    // Compute PTC for current epoch + lookahead epochs
    let current_epoch = state.current_epoch();
    for e in 0..=spec.min_seed_lookahead.as_u64() {
        let epoch = current_epoch.safe_add(e)?;
        let committee_cache = state.initialize_committee_cache_for_lookahead(epoch, spec)?;
        let start_slot = epoch.start_slot(E::slots_per_epoch());
        for i in 0..slots_per_epoch {
            let slot = start_slot.safe_add(i as u64)?;
            let ptc = state.compute_ptc_with_cache(slot, &committee_cache, spec)?;
            let ptc_u64: Vec<u64> = ptc.into_iter().map(|v| v as u64).collect();
            let entry = FixedVector::new(ptc_u64)?;
            ptcs.push(entry);
        }
    }

    *state.ptc_window_mut()? = Vector::new(ptcs)?;

    Ok(())
}

/// Applies any pending deposit for builders, effectively onboarding builders at the fork.
///
/// The `pending_deposits` queue is unbounded, so this function avoids doing expensive work
/// per deposit where possible:
///
/// - Signature verification results are looked up in the `builder_onboarding_cache` (populated
///   ahead of the fork), falling back to inline verification on cache miss.
/// - The builder registry is accumulated in a local `Vec` and written to the state once at the
///   end. This is a deviation from the spec, which calls `add_builder_to_registry` per deposit:
///   scanning the registry for a reusable index on every insertion (quadratic overall) and
///   paying the tree-update cost per push. It is equivalent because the registry is empty at
///   the fork, so every insertion appends.
fn onboard_builders_from_pending_deposits<E: EthSpec>(
    state: &mut BeaconState<E>,
    builder_onboarding_cache: Option<&OnboardBuildersCache>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // The registry must be empty at the fork: `upgrade_state_to_gloas` initializes
    // `builders` to the empty list just before calling this function. The local accumulation
    // below (and its equivalence to the spec's `add_builder_to_registry`) relies on it.
    if !state.builders()?.is_empty() {
        return Err(Error::BuilderRegistryNotEmpty);
    }

    // Clone pending deposits to avoid borrow conflicts when mutating state.
    let current_pending_deposits = state.pending_deposits()?.to_vec();

    let mut pending_deposits: Vec<PendingDeposit> = Vec::new();

    let mut builders: Vec<Builder> = Vec::new();
    let mut builder_pubkey_to_index: HashMap<PublicKeyBytes, u64> = HashMap::new();

    for deposit in &current_pending_deposits {
        // Deposits for existing validators stay in the pending queue.
        if state.get_validator_index(&deposit.pubkey)?.is_some() {
            pending_deposits.push(deposit.clone());
            continue;
        }

        match builder_pubkey_to_index.get(&deposit.pubkey).copied() {
            None => {
                // Deposits without builder withdrawal credentials are for new validators.
                if !is_builder_withdrawal_credential(deposit.withdrawal_credentials, spec) {
                    pending_deposits.push(deposit.clone());
                    continue;
                }

                // If there is a valid pending deposit for a new validator with this pubkey,
                // keep this deposit in the pending queue to be applied to that validator later.
                if is_pending_validator(
                    &pending_deposits,
                    &deposit.pubkey,
                    builder_onboarding_cache,
                    spec,
                ) {
                    pending_deposits.push(deposit.clone());
                    continue;
                }

                if !is_valid_deposit_signature_cached(builder_onboarding_cache, deposit, spec) {
                    continue;
                }

                builder_pubkey_to_index.insert(deposit.pubkey, builders.len() as u64);
                builders.push(Builder::from_deposit(
                    deposit.pubkey,
                    PAYLOAD_BUILDER_VERSION,
                    deposit.withdrawal_credentials,
                    deposit.amount,
                    deposit.slot.epoch(E::slots_per_epoch()),
                    spec,
                )?);
            }
            Some(builder_index) => {
                let builder = builders
                    .get_mut(builder_index as usize)
                    .ok_or(Error::UnknownBuilder(builder_index))?;

                builder.balance.safe_add_assign(deposit.amount)?;
            }
        }
    }

    debug!(
        deposits_processed = current_pending_deposits.len(),
        builders_onboarded = builders.len(),
        deposits_retained = pending_deposits.len(),
        "Onboarded builders at the gloas fork transition"
    );

    *state.builders_mut()? = ProgressiveList::try_from_iter(builders)?;
    state.set_pending_deposits_from_iter(pending_deposits)?;

    Ok(())
}

#[cfg(all(test, not(feature = "fake_crypto")))]
mod tests {
    use super::*;
    use crate::builder_deposits_cache::OnboardBuildersCache;
    use beacon_chain::test_utils::BeaconChainHarness;
    use bls::{Keypair, SignatureBytes};
    use std::sync::Arc;
    use types::{
        DepositData, Epoch, ForkName, MinimalEthSpec, Slot,
        test_utils::generate_deterministic_keypairs,
    };

    type E = MinimalEthSpec;

    const VALIDATOR_COUNT: usize = 8;

    fn builder_credentials(spec: &ChainSpec) -> types::Hash256 {
        let mut credentials = [0u8; 32];
        credentials[0] = spec.builder_withdrawal_prefix_byte;
        types::Hash256::from_slice(&credentials)
    }

    fn eth1_credentials() -> types::Hash256 {
        let mut credentials = [0u8; 32];
        credentials[0] = 0x01;
        types::Hash256::from_slice(&credentials)
    }

    fn make_deposit(
        keypair: &Keypair,
        withdrawal_credentials: types::Hash256,
        amount: u64,
        sign: bool,
        spec: &ChainSpec,
    ) -> PendingDeposit {
        let mut deposit_data = DepositData {
            pubkey: keypair.pk.compress(),
            withdrawal_credentials,
            amount,
            signature: SignatureBytes::empty(),
        };
        if sign {
            deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);
        }
        PendingDeposit {
            pubkey: deposit_data.pubkey,
            withdrawal_credentials: deposit_data.withdrawal_credentials,
            amount: deposit_data.amount,
            signature: deposit_data.signature,
            slot: Slot::new(0),
        }
    }

    /// A Fulu pre-state whose pending deposit queue covers every onboarding branch, along with
    /// the expected onboarding outcome.
    struct OnboardingFixture {
        pre_state: BeaconState<E>,
        spec: Arc<ChainSpec>,
        /// The single deposit expected to register a builder.
        builder_deposit: PendingDeposit,
        /// A top-up for the same builder (top-ups skip signature checks).
        builder_topup_deposit: PendingDeposit,
        /// The deposits expected to remain in the queue after onboarding, in order.
        expected_retained: Vec<PendingDeposit>,
    }

    fn onboarding_fixture() -> OnboardingFixture {
        let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
        spec.gloas_fork_epoch = Some(Epoch::new(1024));
        let spec = Arc::new(spec);

        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        let mut pre_state = harness.get_current_state();

        // Fresh keypairs, distinct from the interop validator set.
        let keypairs = generate_deterministic_keypairs(VALIDATOR_COUNT + 5);
        let new_keys = &keypairs[VALIDATOR_COUNT..];

        let existing_validator_pubkey = harness.validator_keypairs[0].pk.compress();
        let existing_validator_deposit = PendingDeposit {
            pubkey: existing_validator_pubkey,
            withdrawal_credentials: eth1_credentials(),
            amount: 1_000_000_000,
            signature: SignatureBytes::empty(),
            slot: Slot::new(0),
        };

        // A valid deposit for a new *validator* whose pubkey also appears in a later
        // builder-credential deposit: the builder deposit must stay queued.
        let shadowing_validator_deposit = make_deposit(
            &new_keys[0],
            eth1_credentials(),
            32_000_000_000,
            true,
            &spec,
        );
        let shadowed_builder_deposit = make_deposit(
            &new_keys[0],
            builder_credentials(&spec),
            256_000_000_000,
            true,
            &spec,
        );

        // A valid builder registration followed by a top-up (top-ups skip signature checks).
        let builder_deposit = make_deposit(
            &new_keys[1],
            builder_credentials(&spec),
            256_000_000_000,
            true,
            &spec,
        );
        let builder_topup_deposit = make_deposit(
            &new_keys[1],
            builder_credentials(&spec),
            64_000_000_000,
            false,
            &spec,
        );

        // A builder registration with an invalid signature: dropped entirely.
        let invalid_builder_deposit = make_deposit(
            &new_keys[2],
            builder_credentials(&spec),
            256_000_000_000,
            false,
            &spec,
        );

        // A new-validator deposit with an invalid signature: stays queued.
        let invalid_validator_deposit = make_deposit(
            &new_keys[3],
            eth1_credentials(),
            32_000_000_000,
            false,
            &spec,
        );

        pre_state
            .set_pending_deposits_from_iter(vec![
                existing_validator_deposit.clone(),
                shadowing_validator_deposit.clone(),
                shadowed_builder_deposit.clone(),
                builder_deposit.clone(),
                builder_topup_deposit.clone(),
                invalid_builder_deposit,
                invalid_validator_deposit.clone(),
            ])
            .unwrap();

        OnboardingFixture {
            pre_state,
            spec,
            builder_deposit,
            builder_topup_deposit,
            expected_retained: vec![
                existing_validator_deposit,
                shadowing_validator_deposit,
                shadowed_builder_deposit,
                invalid_validator_deposit,
            ],
        }
    }

    fn assert_posts_equal_and_check_semantics(
        fixture: &OnboardingFixture,
        full_post: &BeaconState<E>,
        cached_post: &BeaconState<E>,
    ) {
        // The cached path must be indistinguishable from full verification.
        assert_eq!(
            full_post.builders().unwrap().to_vec(),
            cached_post.builders().unwrap().to_vec()
        );
        assert_eq!(
            full_post.pending_deposits().unwrap().to_vec(),
            cached_post.pending_deposits().unwrap().to_vec()
        );

        // Sanity check the expected onboarding semantics.
        let builders = full_post.builders().unwrap().to_vec();
        assert_eq!(builders.len(), 1);
        assert_eq!(builders[0].pubkey, fixture.builder_deposit.pubkey);
        assert_eq!(
            builders[0].balance,
            fixture.builder_deposit.amount + fixture.builder_topup_deposit.amount
        );

        assert_eq!(
            full_post.pending_deposits().unwrap().to_vec(),
            fixture.expected_retained
        );
    }

    /// Onboarding builders at the fork must produce the same post-state whether signatures are
    /// verified inline or looked up in a pre-seeded `OnboardBuildersCache`.
    #[tokio::test]
    async fn onboarding_with_seeded_cache_matches_full_verification() {
        let fixture = onboarding_fixture();

        let full_post = upgrade_state_to_gloas(
            &mut fixture.pre_state.clone(),
            GloasVerificationContext::FullVerification,
            &fixture.spec,
        )
        .unwrap();

        let cache = OnboardBuildersCache::new(&fixture.spec).unwrap();
        cache.seed_from_state(&fixture.pre_state, &fixture.spec);
        let cached_post = upgrade_state_to_gloas(
            &mut fixture.pre_state.clone(),
            GloasVerificationContext::CachedVerification(&cache),
            &fixture.spec,
        )
        .unwrap();

        assert_posts_equal_and_check_semantics(&fixture, &full_post, &cached_post);
    }

    /// An *unseeded* cache must also match full verification: every lookup misses and falls
    /// back to inline verification, whose results are written back into the cache.
    #[tokio::test]
    async fn onboarding_with_cold_cache_matches_full_verification() {
        let fixture = onboarding_fixture();

        let full_post = upgrade_state_to_gloas(
            &mut fixture.pre_state.clone(),
            GloasVerificationContext::FullVerification,
            &fixture.spec,
        )
        .unwrap();

        let cache = OnboardBuildersCache::new(&fixture.spec).unwrap();
        let cached_post = upgrade_state_to_gloas(
            &mut fixture.pre_state.clone(),
            GloasVerificationContext::CachedVerification(&cache),
            &fixture.spec,
        )
        .unwrap();

        assert_posts_equal_and_check_semantics(&fixture, &full_post, &cached_post);

        // The inline fallback must have written its results back into the cache.
        assert_eq!(
            cache.cached_is_valid_signature(&fixture.builder_deposit),
            Some(true)
        );
    }

    /// Onboarding on a state that already has builders must fail rather than silently wipe the
    /// registry: the local-accumulation optimisation is only spec-equivalent when the registry
    /// is empty at the fork.
    #[tokio::test]
    async fn onboarding_rejects_non_empty_builder_registry() {
        let fixture = onboarding_fixture();

        let mut post = upgrade_state_to_gloas(
            &mut fixture.pre_state.clone(),
            GloasVerificationContext::FullVerification,
            &fixture.spec,
        )
        .unwrap();
        assert!(!post.builders().unwrap().is_empty());

        assert_eq!(
            onboard_builders_from_pending_deposits(&mut post, None, &fixture.spec),
            Err(Error::BuilderRegistryNotEmpty)
        );
    }
}

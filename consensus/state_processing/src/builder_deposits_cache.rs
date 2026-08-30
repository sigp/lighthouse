use crate::metrics;
use crate::per_block_processing::{is_valid_deposit_signature, is_valid_deposit_signature_batch};
use lru::LruCache;
use parking_lot::Mutex;
use tracing::{debug, instrument};
use tree_hash::{Hash256, TreeHash};
use types::{
    BeaconState, ChainSpec, DepositData, EthSpec, PendingDeposit, is_builder_withdrawal_credential,
    new_non_zero_usize,
};

use std::collections::HashSet;
use std::num::NonZeroUsize;

/// This is a very high limit to enable worst case testing.
/// The actual lru storage ends up being quite small in the worst case.
///
/// The internal hashmap representation would take 32 bytes for key + 1 byte for the bool.
/// With additional overhead in the LRU cache, each entry would come out to ~88 bytes.
///
/// So worst case storage is ~25MB.
///
/// In practice, current mainnet gas limits would not allow more than a couple hundred deposits
/// every slot.
const CACHE_SIZE: NonZeroUsize = new_non_zero_usize(262144);

/// A cache that performs signature verification on builder-related `PendingDeposit` entries
/// in the beacon state ahead of the Gloas fork transition and caches the result.
///
/// `onboard_builders_from_pending_deposits` in `upgrade_to_gloas` must verify signatures of
/// builder deposits and same-pubkey validator deposits in the (unbounded) `pending_deposits`
/// queue. Doing this inline at the fork transition could stall the node for a long time; the
/// spec's recommendation (see the note in `specs/gloas/fork.md`) is for clients to pre-verify
/// these signatures and cache the results, which is what this cache implements.
///
/// The key is the `hash_tree_root` of the `DepositData` and the value is the verification
/// result.
///
/// # Domain safety
///
/// All entries in this cache are verification results over `Domain::Deposit` (the validator
/// deposit contract domain). Post-Gloas `BuilderDepositRequest`s sign the *identical*
/// `DepositData` tree hash root but over `Domain::BuilderDeposit`. This cache must therefore
/// never be consulted for builder-contract deposits: sharing it across domains would allow a
/// signature verified against one domain to be accepted for the other.
pub struct OnboardBuildersCache {
    cache: Mutex<LruCache<Hash256, bool>>,
}

impl OnboardBuildersCache {
    /// Returns `None` if gloas is not scheduled currently.
    pub fn new(spec: &ChainSpec) -> Option<Self> {
        if spec.is_gloas_scheduled() {
            Some(Self {
                cache: Mutex::new(LruCache::new(CACHE_SIZE)),
            })
        } else {
            None
        }
    }

    /// Initializes the cache with builder-related `pending_deposits` from the passed state.
    ///
    /// Further block imports that result in additional deposits should be handled by the
    /// [`Self::add_new_pending_deposits`] method.
    #[instrument(skip_all)]
    pub fn seed_from_state<E: EthSpec>(&self, state: &BeaconState<E>, spec: &ChainSpec) {
        self.cache_relevant_from_state(state, spec);
    }

    /// Signature-verifies and caches builder-related `pending_deposits` from `current_state`.
    ///
    /// Uses the full queue so deposits are not missed if seeding has not completed yet.
    #[instrument(skip_all)]
    pub fn add_new_pending_deposits<E: EthSpec>(
        &self,
        current_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) {
        self.cache_relevant_from_state(current_state, spec);
    }

    /// Takes a list of pending deposits, signature verifies them and caches the result.
    fn cache_pending_deposits(&self, deposits: Vec<&PendingDeposit>, spec: &ChainSpec) {
        let mut deposits_to_verify = Vec::new();
        let mut deposit_keys = Vec::new();

        {
            let mut cache = self.cache.lock();
            for deposit in deposits {
                let deposit_data = DepositData {
                    amount: deposit.amount,
                    pubkey: deposit.pubkey,
                    signature: deposit.signature.clone(),
                    withdrawal_credentials: deposit.withdrawal_credentials,
                };
                let key = deposit_data.tree_hash_root();
                if cache.get(&key).is_some() {
                    continue;
                }

                deposit_keys.push(key);
                deposits_to_verify.push(deposit_data);
            }
        }

        if deposits_to_verify.is_empty() {
            return;
        }

        let verified = is_valid_deposit_signature_batch(deposits_to_verify, spec);
        let mut cache = self.cache.lock();
        for (key, value) in deposit_keys.into_iter().zip(verified) {
            cache.push(key, value);
        }
    }

    /// Returns `Some(true)` if the deposit exists in the cache and has a valid signature.
    /// Returns `Some(false)` if the deposit exists and failed signature verification.
    /// Returns `None` if the deposit doesn't exist in the cache.
    pub fn cached_is_valid_signature(&self, deposit: &PendingDeposit) -> Option<bool> {
        let deposit_data = DepositData {
            amount: deposit.amount,
            pubkey: deposit.pubkey,
            signature: deposit.signature.clone(),
            withdrawal_credentials: deposit.withdrawal_credentials,
        };
        self.get(&deposit_data)
    }

    /// Looks up a `DepositData` in the cache by its tree hash root.
    pub fn get(&self, deposit_data: &DepositData) -> Option<bool> {
        let key = deposit_data.tree_hash_root();
        self.cache.lock().get(&key).copied()
    }

    /// Filters to builder-related pending deposits and caches their signature results.
    fn cache_relevant_from_state<E: EthSpec>(&self, state: &BeaconState<E>, spec: &ChainSpec) {
        let deposits = relevant_pending_deposits(state, spec);
        if deposits.is_empty() {
            return;
        }

        debug!(
            pending_deposits_count = deposits.len(),
            slot = %state.slot(),
            "Caching builder-related pending deposits"
        );

        self.cache_pending_deposits(deposits, spec);
    }
}

/// Check a pending deposit's signature via the cache, falling back to inline verification when
/// no cache is available or the deposit is missing from it.
///
/// On a cache miss the inline verification result is written back to the cache, so repeated
/// checks of the same deposit (e.g. the `is_pending_validator` scans during builder onboarding)
/// never verify the same signature twice, even if the cache was not seeded ahead of the fork.
pub fn is_valid_deposit_signature_cached(
    builder_onboarding_cache: Option<&OnboardBuildersCache>,
    deposit: &PendingDeposit,
    spec: &ChainSpec,
) -> bool {
    let deposit_data = DepositData {
        pubkey: deposit.pubkey,
        withdrawal_credentials: deposit.withdrawal_credentials,
        amount: deposit.amount,
        signature: deposit.signature.clone(),
    };

    let Some(cache) = builder_onboarding_cache else {
        return is_valid_deposit_signature(&deposit_data, spec).is_ok();
    };

    let key = deposit_data.tree_hash_root();
    if let Some(valid) = cache.cache.lock().get(&key).copied() {
        metrics::inc_counter(&metrics::BUILDER_DEPOSIT_CACHE_HITS);
        return valid;
    }
    metrics::inc_counter(&metrics::BUILDER_DEPOSIT_CACHE_MISSES);

    // Verify outside the lock so concurrent cache updates are not blocked on BLS verification.
    let valid = is_valid_deposit_signature(&deposit_data, spec).is_ok();
    cache.cache.lock().push(key, valid);
    valid
}

/// Builder-credential pending deposits, plus validator deposits that share a pubkey with one.
fn relevant_pending_deposits<'a, E: EthSpec>(
    state: &'a BeaconState<E>,
    spec: &ChainSpec,
) -> Vec<&'a PendingDeposit> {
    let Ok(pending_deposits) = state.pending_deposits() else {
        return Vec::new();
    };

    let builder_pubkeys: HashSet<_> = pending_deposits
        .iter()
        .filter(|deposit| is_builder_withdrawal_credential(deposit.withdrawal_credentials, spec))
        .map(|deposit| deposit.pubkey)
        .collect();

    if builder_pubkeys.is_empty() {
        return Vec::new();
    }

    pending_deposits
        .iter()
        .filter(|deposit| builder_pubkeys.contains(&deposit.pubkey))
        .collect()
}

#[cfg(all(test, not(feature = "fake_crypto")))]
mod tests {
    use super::*;
    use bls::{Keypair, SignatureBytes};
    use std::sync::LazyLock;
    use types::{ForkName, MainnetEthSpec, Slot};

    static KEYPAIRS: LazyLock<Vec<Keypair>> =
        LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(10));

    fn gloas_spec() -> ChainSpec {
        ForkName::Gloas.make_genesis_spec(MainnetEthSpec::default_spec())
    }

    fn non_gloas_spec() -> ChainSpec {
        ForkName::Fulu.make_genesis_spec(MainnetEthSpec::default_spec())
    }

    fn builder_credentials(spec: &ChainSpec) -> Hash256 {
        let mut credentials = [0u8; 32];
        credentials[0] = spec.builder_withdrawal_prefix_byte;
        Hash256::from_slice(&credentials)
    }

    fn non_builder_credentials() -> Hash256 {
        let mut credentials = [0u8; 32];
        credentials[0] = 0x01; // ETH1 withdrawal credentials
        Hash256::from_slice(&credentials)
    }

    fn make_valid_builder_deposit(keypair: &Keypair, spec: &ChainSpec) -> PendingDeposit {
        let withdrawal_credentials = builder_credentials(spec);
        let mut deposit_data = DepositData {
            pubkey: keypair.pk.compress(),
            withdrawal_credentials,
            amount: 256_000_000_000,
            signature: SignatureBytes::empty(),
        };
        deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);

        PendingDeposit {
            pubkey: deposit_data.pubkey,
            withdrawal_credentials: deposit_data.withdrawal_credentials,
            amount: deposit_data.amount,
            signature: deposit_data.signature,
            slot: Slot::new(0),
        }
    }

    fn make_invalid_builder_deposit(keypair: &Keypair, spec: &ChainSpec) -> PendingDeposit {
        let withdrawal_credentials = builder_credentials(spec);
        PendingDeposit {
            pubkey: keypair.pk.compress(),
            withdrawal_credentials,
            amount: 256_000_000_000,
            signature: SignatureBytes::empty(),
            slot: Slot::new(0),
        }
    }

    fn make_non_builder_deposit(keypair: &Keypair, spec: &ChainSpec) -> PendingDeposit {
        let mut deposit_data = DepositData {
            pubkey: keypair.pk.compress(),
            withdrawal_credentials: non_builder_credentials(),
            amount: 32_000_000_000,
            signature: SignatureBytes::empty(),
        };
        deposit_data.signature = deposit_data.create_signature(&keypair.sk, spec);

        PendingDeposit {
            pubkey: deposit_data.pubkey,
            withdrawal_credentials: deposit_data.withdrawal_credentials,
            amount: deposit_data.amount,
            signature: deposit_data.signature,
            slot: Slot::new(0),
        }
    }

    fn make_invalid_non_builder_deposit(keypair: &Keypair) -> PendingDeposit {
        PendingDeposit {
            pubkey: keypair.pk.compress(),
            withdrawal_credentials: non_builder_credentials(),
            amount: 32_000_000_000,
            signature: SignatureBytes::empty(),
            slot: Slot::new(0),
        }
    }

    #[test]
    fn new_returns_none_when_gloas_not_scheduled() {
        let spec = non_gloas_spec();
        assert!(OnboardBuildersCache::new(&spec).is_none());
    }

    #[test]
    fn new_returns_some_when_gloas_scheduled() {
        let spec = gloas_spec();
        assert!(OnboardBuildersCache::new(&spec).is_some());
    }

    #[test]
    fn cache_valid_builder_deposit() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);

        cache.cache_pending_deposits(vec![&deposit], &spec);

        assert_eq!(cache.cached_is_valid_signature(&deposit), Some(true));
    }

    #[test]
    fn cache_invalid_builder_deposit() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let deposit = make_invalid_builder_deposit(&KEYPAIRS[0], &spec);

        cache.cache_pending_deposits(vec![&deposit], &spec);

        assert_eq!(cache.cached_is_valid_signature(&deposit), Some(false));
    }

    #[test]
    fn cache_miss_returns_none() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);

        assert_eq!(cache.cached_is_valid_signature(&deposit), None);
    }

    #[test]
    fn duplicate_deposits_not_reverified() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);

        cache.cache_pending_deposits(vec![&deposit], &spec);
        // Second call with same deposit - should be skipped (already in cache)
        cache.cache_pending_deposits(vec![&deposit], &spec);

        assert_eq!(cache.cached_is_valid_signature(&deposit), Some(true));
    }

    #[test]
    fn multiple_valid_and_invalid_deposits() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();

        let valid_0 = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
        let valid_1 = make_valid_builder_deposit(&KEYPAIRS[1], &spec);
        let invalid_0 = make_invalid_builder_deposit(&KEYPAIRS[2], &spec);
        let invalid_1 = make_invalid_builder_deposit(&KEYPAIRS[3], &spec);

        cache.cache_pending_deposits(vec![&valid_0, &invalid_0, &valid_1, &invalid_1], &spec);

        assert_eq!(cache.cached_is_valid_signature(&valid_0), Some(true));
        assert_eq!(cache.cached_is_valid_signature(&valid_1), Some(true));
        assert_eq!(cache.cached_is_valid_signature(&invalid_0), Some(false));
        assert_eq!(cache.cached_is_valid_signature(&invalid_1), Some(false));
    }

    #[test]
    fn get_by_deposit_data() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);

        let deposit_data = DepositData {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
            signature: deposit.signature.clone(),
        };

        cache.cache_pending_deposits(vec![&deposit], &spec);

        assert_eq!(cache.get(&deposit_data), Some(true));
    }

    #[test]
    fn empty_deposits_list_is_noop() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();

        cache.cache_pending_deposits(vec![], &spec);
        // No panic, no entries
    }

    mod filtering {
        use super::*;
        use beacon_chain::test_utils::BeaconChainHarness;
        use std::sync::Arc;
        use types::{Epoch, MinimalEthSpec};

        fn fulu_state_at_slot(
            slot: Slot,
            deposits: Vec<PendingDeposit>,
            spec: &Arc<ChainSpec>,
        ) -> types::BeaconState<MinimalEthSpec> {
            let harness = BeaconChainHarness::builder(MinimalEthSpec)
                .spec(spec.clone())
                .deterministic_keypairs(4)
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();
            let mut state = harness.get_current_state();
            *state.slot_mut() = slot;
            state.set_pending_deposits_from_iter(deposits).unwrap();
            state
        }

        fn fulu_spec_with_gloas_scheduled() -> Arc<ChainSpec> {
            let mut spec = ForkName::Fulu.make_genesis_spec(MinimalEthSpec::default_spec());
            spec.gloas_fork_epoch = Some(Epoch::new(1024));
            Arc::new(spec)
        }

        fn deposit_at_slot(mut deposit: PendingDeposit, slot: Slot) -> PendingDeposit {
            deposit.slot = slot;
            deposit
        }

        #[tokio::test]
        async fn unrelated_validator_deposits_are_not_cached() {
            let spec = fulu_spec_with_gloas_scheduled();
            let unrelated = make_non_builder_deposit(&KEYPAIRS[0], &spec);
            let invalid_unrelated = make_invalid_non_builder_deposit(&KEYPAIRS[1]);
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![unrelated.clone(), invalid_unrelated.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.seed_from_state(&state, &spec);

            assert_eq!(cache.cached_is_valid_signature(&unrelated), None);
            assert_eq!(cache.cached_is_valid_signature(&invalid_unrelated), None);
        }

        #[tokio::test]
        async fn builder_cached_unrelated_validator_not_cached() {
            let spec = fulu_spec_with_gloas_scheduled();
            let builder_deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
            let unrelated = make_non_builder_deposit(&KEYPAIRS[1], &spec);
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![unrelated.clone(), builder_deposit.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.seed_from_state(&state, &spec);

            assert_eq!(
                cache.cached_is_valid_signature(&builder_deposit),
                Some(true)
            );
            assert_eq!(cache.cached_is_valid_signature(&unrelated), None);
        }

        #[tokio::test]
        async fn same_pubkey_validator_and_builder_are_cached() {
            let spec = fulu_spec_with_gloas_scheduled();
            let validator_deposit = make_non_builder_deposit(&KEYPAIRS[0], &spec);
            let builder_deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![validator_deposit.clone(), builder_deposit.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.seed_from_state(&state, &spec);

            assert_eq!(
                cache.cached_is_valid_signature(&validator_deposit),
                Some(true)
            );
            assert_eq!(
                cache.cached_is_valid_signature(&builder_deposit),
                Some(true)
            );
        }

        #[tokio::test]
        async fn invalid_same_pubkey_validator_is_cached_as_false() {
            let spec = fulu_spec_with_gloas_scheduled();
            let invalid_validator = make_invalid_non_builder_deposit(&KEYPAIRS[0]);
            let builder_deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![invalid_validator.clone(), builder_deposit.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.seed_from_state(&state, &spec);

            assert_eq!(
                cache.cached_is_valid_signature(&invalid_validator),
                Some(false)
            );
            assert_eq!(
                cache.cached_is_valid_signature(&builder_deposit),
                Some(true)
            );
        }

        #[tokio::test]
        async fn invalid_builder_is_cached_as_false() {
            let spec = fulu_spec_with_gloas_scheduled();
            let invalid_builder = make_invalid_builder_deposit(&KEYPAIRS[0], &spec);
            let state = fulu_state_at_slot(Slot::new(5), vec![invalid_builder.clone()], &spec);

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.seed_from_state(&state, &spec);

            assert_eq!(
                cache.cached_is_valid_signature(&invalid_builder),
                Some(false)
            );
        }

        #[tokio::test]
        async fn add_new_caches_older_relevant_deposits() {
            let spec = fulu_spec_with_gloas_scheduled();
            let older_0 = deposit_at_slot(
                make_valid_builder_deposit(&KEYPAIRS[0], &spec),
                Slot::new(0),
            );
            let older_3 = deposit_at_slot(
                make_valid_builder_deposit(&KEYPAIRS[1], &spec),
                Slot::new(3),
            );
            let current = deposit_at_slot(
                make_valid_builder_deposit(&KEYPAIRS[2], &spec),
                Slot::new(5),
            );
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![older_0.clone(), older_3.clone(), current.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            assert_eq!(cache.cached_is_valid_signature(&older_0), Some(true));
            assert_eq!(cache.cached_is_valid_signature(&older_3), Some(true));
            assert_eq!(cache.cached_is_valid_signature(&current), Some(true));
        }

        #[tokio::test]
        async fn add_new_caches_older_relevant_when_no_current_slot_deposits() {
            let spec = fulu_spec_with_gloas_scheduled();
            let deposits: Vec<_> = (0..3)
                .map(|i| {
                    deposit_at_slot(
                        make_valid_builder_deposit(&KEYPAIRS[i], &spec),
                        Slot::new(3),
                    )
                })
                .collect();
            let state = fulu_state_at_slot(Slot::new(5), deposits.clone(), &spec);

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            for deposit in &deposits {
                assert_eq!(cache.cached_is_valid_signature(deposit), Some(true));
            }
        }

        #[tokio::test]
        async fn add_new_caches_older_validator_when_builder_arrives_later() {
            let spec = fulu_spec_with_gloas_scheduled();
            let older_validator =
                deposit_at_slot(make_non_builder_deposit(&KEYPAIRS[0], &spec), Slot::new(1));
            let current_builder = deposit_at_slot(
                make_valid_builder_deposit(&KEYPAIRS[0], &spec),
                Slot::new(5),
            );
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![older_validator.clone(), current_builder.clone()],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            assert_eq!(
                cache.cached_is_valid_signature(&older_validator),
                Some(true)
            );
            assert_eq!(
                cache.cached_is_valid_signature(&current_builder),
                Some(true)
            );
        }
    }
}

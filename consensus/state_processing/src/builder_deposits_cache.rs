use crate::metrics;
use crate::per_block_processing::{is_valid_deposit_signature, is_valid_deposit_signature_batch};
use lru::LruCache;
use parking_lot::Mutex;
use tracing::{debug, instrument};
use tree_hash::{Hash256, TreeHash};
use types::{BeaconState, ChainSpec, DepositData, EthSpec, PendingDeposit, new_non_zero_usize};

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

/// A cache that performs signature verification on `PendingDeposit` entries in the
/// beacon state ahead of the Gloas fork transition and caches the result.
///
/// `onboard_builders_from_pending_deposits` in `upgrade_to_gloas` must decide, for every entry
/// in the (unbounded) `pending_deposits` queue, whether its signature is valid. Doing this
/// inline at the fork transition could stall the node for a long time; the spec's
/// recommendation (see the note in `specs/gloas/fork.md`) is for clients to pre-verify these
/// signatures and cache the results, which is what this cache implements.
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

    /// Initializes the cache with all the `pending_deposits` from the passed state
    /// that would need to be onboarded at the gloas fork.
    ///
    /// Further block imports that result in additional deposits should be handled by the
    /// [`Self::add_new_pending_deposits`] method.
    #[instrument(skip_all)]
    pub fn seed_from_state<E: EthSpec>(&self, state: &BeaconState<E>, spec: &ChainSpec) {
        let Ok(pending_deposits) = state.pending_deposits() else {
            return;
        };
        let pending_deposits = pending_deposits.iter().collect::<Vec<_>>();
        if pending_deposits.is_empty() {
            return;
        }

        debug!(
            pending_deposits_count = pending_deposits.len(),
            "Seeding builder onboarding cache from head state"
        );

        self.cache_pending_deposits(pending_deposits, spec);
    }

    /// Gets the new deposits added to the `pending_deposits` queue for `state.slot()`.
    /// Signature verifies and caches them for later use.
    #[instrument(skip_all)]
    pub fn add_new_pending_deposits<E: EthSpec>(
        &self,
        current_state: &BeaconState<E>,
        spec: &ChainSpec,
    ) {
        let pending_deposits = pending_deposits_to_verify(current_state);
        if pending_deposits.is_empty() {
            return;
        }

        debug!(
            pending_deposits_count = pending_deposits.len(),
            slot = %current_state.slot(),
            "Adding new pending deposits to builder onboarding cache"
        );

        self.cache_pending_deposits(pending_deposits, spec);
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

/// Returns a list of `pending_deposits` that were added for the same slot as the passed state.
fn pending_deposits_to_verify<E: EthSpec>(state: &BeaconState<E>) -> Vec<&PendingDeposit> {
    let current_slot = state.slot();
    let Ok(pending_deposits) = state.pending_deposits() else {
        return Vec::new();
    };
    // Get the index of the first `pending_deposit` for the current slot
    //
    // Need to do this roundabout way because milhouse iterators aren't double ended, so
    // rev().take_while() won't work.
    let mut first_current_slot_index = 0;
    for index in (0..pending_deposits.len()).rev() {
        if pending_deposits
            .get(index)
            .is_some_and(|deposit| deposit.slot != current_slot)
        {
            first_current_slot_index = index.saturating_add(1);
            break;
        }
    }

    if let Ok(deposits) = pending_deposits.iter_from(first_current_slot_index) {
        deposits.collect()
    } else {
        Vec::new()
    }
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
    fn non_builder_pending_deposits_are_cached() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let non_builder = make_non_builder_deposit(&KEYPAIRS[0], &spec);

        cache.cache_pending_deposits(vec![&non_builder], &spec);

        assert_eq!(cache.cached_is_valid_signature(&non_builder), Some(true));
    }

    #[test]
    fn invalid_non_builder_pending_deposits_are_cached() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let non_builder = make_invalid_non_builder_deposit(&KEYPAIRS[0]);

        cache.cache_pending_deposits(vec![&non_builder], &spec);

        assert_eq!(cache.cached_is_valid_signature(&non_builder), Some(false));
    }

    #[test]
    fn mixed_pending_deposits_are_cached() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let builder_deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
        let non_builder_deposit = make_non_builder_deposit(&KEYPAIRS[1], &spec);

        cache.cache_pending_deposits(vec![&non_builder_deposit, &builder_deposit], &spec);

        assert_eq!(
            cache.cached_is_valid_signature(&builder_deposit),
            Some(true)
        );
        assert_eq!(
            cache.cached_is_valid_signature(&non_builder_deposit),
            Some(true)
        );
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

    mod incremental_updates {
        use super::*;
        use beacon_chain::test_utils::BeaconChainHarness;
        use std::sync::Arc;
        use types::{Epoch, MinimalEthSpec};

        /// A Fulu state (gloas scheduled) at the given slot, as `add_new_pending_deposits`
        /// sees it after a block import.
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

        fn deposit_at_slot(keypair: &Keypair, slot: Slot, spec: &ChainSpec) -> PendingDeposit {
            let mut deposit = make_valid_builder_deposit(keypair, spec);
            deposit.slot = slot;
            deposit
        }

        /// Only the deposits appended by the state's own slot are verified: older entries are
        /// assumed to have been cached when their block was imported (or by seeding).
        #[tokio::test]
        async fn add_new_pending_deposits_only_caches_current_slot_tail() {
            let spec = fulu_spec_with_gloas_scheduled();
            let older_0 = deposit_at_slot(&KEYPAIRS[0], Slot::new(0), &spec);
            let older_3 = deposit_at_slot(&KEYPAIRS[1], Slot::new(3), &spec);
            let current_a = deposit_at_slot(&KEYPAIRS[2], Slot::new(5), &spec);
            let current_b = deposit_at_slot(&KEYPAIRS[3], Slot::new(5), &spec);
            let state = fulu_state_at_slot(
                Slot::new(5),
                vec![
                    older_0.clone(),
                    older_3.clone(),
                    current_a.clone(),
                    current_b.clone(),
                ],
                &spec,
            );

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            assert_eq!(cache.cached_is_valid_signature(&older_0), None);
            assert_eq!(cache.cached_is_valid_signature(&older_3), None);
            assert_eq!(cache.cached_is_valid_signature(&current_a), Some(true));
            assert_eq!(cache.cached_is_valid_signature(&current_b), Some(true));
        }

        #[tokio::test]
        async fn add_new_pending_deposits_caches_all_when_all_current_slot() {
            let spec = fulu_spec_with_gloas_scheduled();
            let deposits: Vec<_> = (0..3)
                .map(|i| deposit_at_slot(&KEYPAIRS[i], Slot::new(5), &spec))
                .collect();
            let state = fulu_state_at_slot(Slot::new(5), deposits.clone(), &spec);

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            for deposit in &deposits {
                assert_eq!(cache.cached_is_valid_signature(deposit), Some(true));
            }
        }

        #[tokio::test]
        async fn add_new_pending_deposits_noop_when_no_current_slot_deposits() {
            let spec = fulu_spec_with_gloas_scheduled();
            let deposits: Vec<_> = (0..3)
                .map(|i| deposit_at_slot(&KEYPAIRS[i], Slot::new(3), &spec))
                .collect();
            let state = fulu_state_at_slot(Slot::new(5), deposits.clone(), &spec);

            let cache = OnboardBuildersCache::new(&spec).unwrap();
            cache.add_new_pending_deposits(&state, &spec);

            for deposit in &deposits {
                assert_eq!(cache.cached_is_valid_signature(deposit), None);
            }
        }
    }
}

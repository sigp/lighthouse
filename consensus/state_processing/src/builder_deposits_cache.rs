use crate::per_block_processing::is_valid_deposit_signature_batch;
use lru::LruCache;
use parking_lot::Mutex;
use tracing::{debug, instrument};
use tree_hash::{Hash256, TreeHash};
use types::{
    BeaconState, ChainSpec, DepositData, DepositRequest, EthSpec, PendingDeposit,
    is_builder_withdrawal_credential, new_non_zero_usize,
};

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

/// A simple cache that performs signature verification on `PendingDeposit` entries in the
/// beacon state for 0x03 credentials and caches the result.
///
/// The key is the hash_tree_root of the `Deposit` and the value is the verification result.
/// In gloas, there are 2 places where we need to do bulk signature verification:
/// 1. `onboard_builders_from_pending_deposits` in `upgrade_to_gloas` happens at the fork transition.
///    If the `pending_deposits` queue at fork has many signatures to verify, then verifying them
///    in the hot path could be very expensive.
/// 2. `process_deposit_requests_post_gloas` in `process_operations` can contain upto 8192 signatures
///    to verify in the hot block verification path based on limits today. Since the deposits are
///    received a couple seconds before the actual deposits processing, we can cache those signatures
///    too to ensure the deposit processing is just a lookup operation in the worst case.
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
        let Some(pending_deposits) = state.pending_deposits().ok() else {
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

    /// Gets the new deposits added to the `pending_cache` for `state.slot.
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
        let mut builder_deposits = Vec::new();
        let mut builder_deposit_keys = Vec::new();

        {
            let mut cache = self.cache.lock();
            for deposit in deposits {
                if !is_builder_withdrawal_credential(deposit.withdrawal_credentials, spec) {
                    continue;
                }

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

                builder_deposit_keys.push(key);
                builder_deposits.push(deposit_data);
            }
        }

        if builder_deposits.is_empty() {
            return;
        }

        debug!(
            builder_deposits_count = builder_deposits.len(),
            "Pre-verifying builder onboarding deposit signatures"
        );

        let verified = is_valid_deposit_signature_batch(builder_deposits, spec);
        let mut cache = self.cache.lock();
        for (key, value) in builder_deposit_keys.into_iter().zip(verified) {
            cache.push(key, value);
        }
    }

    /// Pre-verifies builder deposit signatures from execution payload deposit requests
    /// and caches the results for later use during `process_deposit_requests_post_gloas`.
    #[instrument(skip_all)]
    pub fn cache_deposit_requests(&self, deposit_requests: &[DepositRequest], spec: &ChainSpec) {
        let mut builder_deposits = Vec::new();
        let mut builder_deposit_keys = Vec::new();

        {
            let mut cache = self.cache.lock();
            for request in deposit_requests {
                if !is_builder_withdrawal_credential(request.withdrawal_credentials, spec) {
                    continue;
                }

                let deposit_data = DepositData {
                    amount: request.amount,
                    pubkey: request.pubkey,
                    signature: request.signature.clone(),
                    withdrawal_credentials: request.withdrawal_credentials,
                };
                let key = deposit_data.tree_hash_root();
                if cache.get(&key).is_some() {
                    continue;
                }

                builder_deposit_keys.push(key);
                builder_deposits.push(deposit_data);
            }
        }

        if builder_deposits.is_empty() {
            return;
        }

        debug!(
            builder_deposits_count = builder_deposits.len(),
            "Pre-verifying builder deposit signatures from payload envelope"
        );

        let verified = is_valid_deposit_signature_batch(builder_deposits, spec);
        let mut cache = self.cache.lock();
        for (key, value) in builder_deposit_keys.into_iter().zip(verified) {
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

/// Returns a list of `pending_deposits` that were added for the same slot as the passed state.
fn pending_deposits_to_verify<E: EthSpec>(state: &BeaconState<E>) -> Vec<&PendingDeposit> {
    let current_slot = state.slot();
    let Some(pending_deposits) = state.pending_deposits().ok() else {
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

    pending_deposits
        .iter()
        .skip(first_current_slot_index)
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
    fn non_builder_deposits_filtered_out() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let non_builder = make_non_builder_deposit(&KEYPAIRS[0], &spec);

        cache.cache_pending_deposits(vec![&non_builder], &spec);

        assert_eq!(cache.cached_is_valid_signature(&non_builder), None);
    }

    #[test]
    fn mixed_deposits_only_caches_builder() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let builder_deposit = make_valid_builder_deposit(&KEYPAIRS[0], &spec);
        let non_builder_deposit = make_non_builder_deposit(&KEYPAIRS[1], &spec);

        cache.cache_pending_deposits(vec![&non_builder_deposit, &builder_deposit], &spec);

        assert_eq!(
            cache.cached_is_valid_signature(&builder_deposit),
            Some(true)
        );
        assert_eq!(cache.cached_is_valid_signature(&non_builder_deposit), None);
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

        cache.cache_pending_deposits(
            vec![&valid_0, &invalid_0, &valid_1, &invalid_1],
            &spec,
        );

        assert_eq!(cache.cached_is_valid_signature(&valid_0), Some(true));
        assert_eq!(cache.cached_is_valid_signature(&valid_1), Some(true));
        assert_eq!(cache.cached_is_valid_signature(&invalid_0), Some(false));
        assert_eq!(cache.cached_is_valid_signature(&invalid_1), Some(false));
    }

    #[test]
    fn cache_deposit_requests_works() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();
        let withdrawal_credentials = builder_credentials(&spec);

        let mut deposit_data = DepositData {
            pubkey: KEYPAIRS[0].pk.compress(),
            withdrawal_credentials,
            amount: 256_000_000_000,
            signature: SignatureBytes::empty(),
        };
        deposit_data.signature = deposit_data.create_signature(&KEYPAIRS[0].sk, &spec);

        let request = DepositRequest {
            pubkey: deposit_data.pubkey,
            withdrawal_credentials: deposit_data.withdrawal_credentials,
            amount: deposit_data.amount,
            signature: deposit_data.signature.clone(),
            index: 0,
        };

        cache.cache_deposit_requests(&[request], &spec);

        assert_eq!(cache.get(&deposit_data), Some(true));
    }

    #[test]
    fn cache_deposit_requests_filters_non_builder() {
        let spec = gloas_spec();
        let cache = OnboardBuildersCache::new(&spec).unwrap();

        let mut deposit_data = DepositData {
            pubkey: KEYPAIRS[0].pk.compress(),
            withdrawal_credentials: non_builder_credentials(),
            amount: 32_000_000_000,
            signature: SignatureBytes::empty(),
        };
        deposit_data.signature = deposit_data.create_signature(&KEYPAIRS[0].sk, &spec);

        let request = DepositRequest {
            pubkey: deposit_data.pubkey,
            withdrawal_credentials: deposit_data.withdrawal_credentials,
            amount: deposit_data.amount,
            signature: deposit_data.signature.clone(),
            index: 0,
        };

        cache.cache_deposit_requests(&[request], &spec);

        assert_eq!(cache.get(&deposit_data), None);
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
        cache.cache_deposit_requests(&[], &spec);
        // No panic, no entries
    }
}

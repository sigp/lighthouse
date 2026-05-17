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
/// If the `pending_deposits` queue at fork has many signatures to verify, then verifying them
/// in the hot path could be very expensive.
/// 2. `process_deposit_requests_post_gloas` in `process_operations` can contain upto 8192 signatures to
/// verify in the hot block verification path based on limits today. Since the deposits are received a
/// couple seconds before the actual deposits processing, we can cache those signatures too to ensure
/// the deposit processing is just a lookup operation in the worst case.
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

        self.cache_pending_deposits(pending_deposits, &spec);
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
        for (key, value) in builder_deposit_keys.into_iter().zip(verified.into_iter()) {
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
        for (key, value) in builder_deposit_keys.into_iter().zip(verified.into_iter()) {
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
            first_current_slot_index = index + 1;
            break;
        }
    }

    pending_deposits
        .iter()
        .skip(first_current_slot_index)
        .collect()
}

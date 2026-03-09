//! Beacon chain database invariant checks.
//!
//! Builds the `InvariantContext` from beacon chain state and delegates all checks
//! to `HotColdDB::check_invariants`.

use crate::BeaconChain;
use crate::beacon_chain::BeaconChainTypes;
use store::invariants::{InvariantCheckResult, InvariantContext};

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Run all database invariant checks.
    ///
    /// Collects context from fork choice, state cache, custody columns, and pubkey cache,
    /// then delegates to the store-level `check_invariants` method.
    pub fn check_database_invariants(&self) -> Result<InvariantCheckResult, store::Error> {
        let fork_choice_blocks = {
            let fc = self.canonical_head.fork_choice_read_lock();
            let proto_array = fc.proto_array().core_proto_array();
            proto_array
                .nodes
                .iter()
                .map(|node| (node.root, node.slot))
                .collect()
        };

        let custody_context = self.data_availability_checker.custody_context();

        let ctx = InvariantContext {
            fork_choice_blocks,
            state_cache_roots: self.store.state_cache.lock().state_roots(),
            custody_columns: custody_context
                .custody_columns_for_epoch(None, &self.spec)
                .to_vec(),
            pubkey_cache_count: self.validator_pubkey_cache.read().len(),
        };

        self.store.check_invariants(&ctx)
    }
}

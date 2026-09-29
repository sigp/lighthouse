//! Beacon chain database invariant checks.
//!
//! Builds the `InvariantContext` from beacon chain state and delegates all checks
//! to `HotColdDB::check_invariants`.

use crate::BeaconChain;
use crate::beacon_chain::BeaconChainTypes;
use store::invariants::{InvariantCheckResult, InvariantContext};
use types::EthSpec;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Run all database invariant checks.
    ///
    /// Collects context from fork choice, state cache, custody columns, and pubkey cache,
    /// then delegates to the store-level `check_invariants` method.
    pub fn check_database_invariants(&self) -> Result<InvariantCheckResult, store::Error> {
        let (fork_choice_blocks, fork_choice_payloads) = {
            let fc = self.canonical_head.fork_choice_read_lock();
            let proto_array = fc.proto_array().core_proto_array();
            let finalized_slot = fc
                .finalized_checkpoint()
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            let mut blocks = Vec::new();
            let mut payloads = Vec::new();
            for node in &proto_array.nodes {
                // Pruned fork blocks may linger in the proto-array but are legitimately
                // absent from the database.
                if !fc.is_finalized_checkpoint_or_descendant(node.root()) {
                    continue;
                }
                blocks.push((node.root(), node.slot()));
                // Receipt, not canonicity, determines whether an unfinalized Gloas block
                // needs a summary. Pre-Gloas nodes do not have a payload_received field.
                if node.slot() > finalized_slot
                    && node.payload_received().is_ok_and(|received| received)
                {
                    payloads.push((node.root(), node.slot()));
                }
            }
            (blocks, payloads)
        };

        let custody_context = self.custody_context.clone();

        let ctx = InvariantContext {
            fork_choice_blocks,
            fork_choice_payloads,
            state_cache_roots: self.store.state_cache.lock().state_roots(),
            custody_columns: custody_context.custody_columns_for_epoch(None).to_vec(),
            pubkey_cache_pubkeys: {
                let cache = self.validator_pubkey_cache.read();
                (0..cache.len())
                    .filter_map(|i| {
                        cache.get(i).map(|pk| {
                            use store::StoreItem;
                            crate::validator_pubkey_cache::DatabasePubkey::from_pubkey(pk)
                                .as_store_bytes()
                        })
                    })
                    .collect()
            },
        };

        self.store.check_invariants(&ctx)
    }
}

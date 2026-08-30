use hashlink::lru_cache::LruCache;
use parking_lot::RwLock;
use types::{ExecPayload, ExecutionBlockHash};

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};

/// At one payload per slot, this holds 32 mainnet epochs. Empty blocks do not use entries.
const PAYLOAD_GAS_LIMIT_CACHE_CAPACITY: usize = 1_024;

/// Gas limits from execution payloads observed during gossip validation, import, or startup.
pub struct ObservedExecutionPayloads {
    gas_limits: RwLock<LruCache<ExecutionBlockHash, u64>>,
}

impl Default for ObservedExecutionPayloads {
    fn default() -> Self {
        Self {
            gas_limits: RwLock::new(LruCache::new(PAYLOAD_GAS_LIMIT_CACHE_CAPACITY)),
        }
    }
}

impl ObservedExecutionPayloads {
    pub fn get_gas_limit(&self, block_hash: ExecutionBlockHash) -> Option<u64> {
        self.gas_limits.read().peek(&block_hash).copied()
    }

    pub(crate) fn insert(&self, block_hash: ExecutionBlockHash, gas_limit: u64) {
        let mut gas_limits = self.gas_limits.write();
        if !gas_limits.contains_key(&block_hash) {
            gas_limits.insert(block_hash, gas_limit);
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Seed the cache from the head when its payload is directly available.
    pub(crate) fn initialize_observed_execution_payloads(&self) -> Result<(), BeaconChainError> {
        if !self.spec.is_gloas_scheduled() {
            return Ok(());
        }

        let head = self.canonical_head.cached_head();
        let block = head.snapshot.beacon_block.message();

        if !block.fork_name_unchecked().gloas_enabled() {
            if let Ok(payload) = block.body().execution_payload()
                && payload.block_hash() != ExecutionBlockHash::zero()
            {
                self.observed_execution_payloads
                    .insert(payload.block_hash(), payload.gas_limit());
            }
        } else if block.slot() == self.spec.genesis_slot {
            let bid = block
                .body()
                .signed_execution_payload_bid()
                .map_err(BeaconChainError::BeaconStateError)?
                .message();
            self.observed_execution_payloads
                .insert(bid.parent_block_hash(), bid.gas_limit());
        } else if let Some(envelope) = head.snapshot.execution_envelope.as_ref() {
            let payload = &envelope.message.payload;
            self.observed_execution_payloads
                .insert(payload.block_hash, payload.gas_limit);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use fixed_bytes::FixedBytesExtended;
    use types::{ExecutionBlockHash, Hash256};

    use super::{ObservedExecutionPayloads, PAYLOAD_GAS_LIMIT_CACHE_CAPACITY};

    #[test]
    fn evicts_oldest_payload_when_full() {
        let payloads = ObservedExecutionPayloads::default();
        let oldest = execution_block_hash(0);

        for value in 0..=PAYLOAD_GAS_LIMIT_CACHE_CAPACITY as u64 {
            payloads.insert(execution_block_hash(value), value);
        }

        assert_eq!(
            payloads.gas_limits.read().len(),
            PAYLOAD_GAS_LIMIT_CACHE_CAPACITY
        );
        assert_eq!(payloads.get_gas_limit(oldest), None);
        assert_eq!(
            payloads.get_gas_limit(execution_block_hash(
                PAYLOAD_GAS_LIMIT_CACHE_CAPACITY as u64
            )),
            Some(PAYLOAD_GAS_LIMIT_CACHE_CAPACITY as u64)
        );
    }

    #[test]
    fn keeps_first_gas_limit_for_execution_block_hash() {
        let payloads = ObservedExecutionPayloads::default();
        let block_hash = execution_block_hash(1);

        payloads.insert(block_hash, 30_000_000);
        payloads.insert(block_hash, 36_000_000);

        assert_eq!(payloads.get_gas_limit(block_hash), Some(30_000_000));
    }

    fn execution_block_hash(value: u64) -> ExecutionBlockHash {
        ExecutionBlockHash::from_root(Hash256::from_low_u64_be(value))
    }
}

use parking_lot::RwLock;
use proto_array::Block as ProtoBlock;
use std::collections::{HashMap, HashSet};
use tracing::warn;
use types::{ExecPayload, ExecutionBlockHash, Hash256, Slot};

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, beacon_chain::BeaconForkChoice};

/// Gas limits from execution payloads observed through gossip or another trusted source.
#[derive(Default)]
pub struct ObservedExecutionPayloads {
    gas_limits: RwLock<HashMap<ExecutionBlockHash, u64>>,
}

impl ObservedExecutionPayloads {
    pub fn get_gas_limit(&self, block_hash: ExecutionBlockHash) -> Option<u64> {
        self.gas_limits.read().get(&block_hash).copied()
    }

    pub(crate) fn insert(&self, block_hash: ExecutionBlockHash, gas_limit: u64) {
        self.gas_limits
            .write()
            .entry(block_hash)
            .or_insert(gas_limit);
    }

    pub(crate) fn retain(&self, block_hashes: &HashSet<ExecutionBlockHash>) {
        self.gas_limits
            .write()
            .retain(|block_hash, _| block_hashes.contains(block_hash));
    }
}

enum StoredPayloadSource {
    GloasGenesis {
        block_root: Hash256,
        expected_block_hash: ExecutionBlockHash,
    },
    GloasEnvelope {
        block_root: Hash256,
        expected_block_hash: ExecutionBlockHash,
    },
    PreGloasBlock {
        block_root: Hash256,
        expected_block_hash: ExecutionBlockHash,
    },
}

fn stored_payload_source(block: &ProtoBlock) -> Option<StoredPayloadSource> {
    if let (Some(parent_block_hash), Some(block_hash)) = (
        block.execution_payload_parent_hash,
        block.execution_payload_block_hash,
    ) {
        if block.slot == Slot::new(0) {
            return Some(StoredPayloadSource::GloasGenesis {
                block_root: block.root,
                expected_block_hash: parent_block_hash,
            });
        }

        if block.payload_received {
            return Some(StoredPayloadSource::GloasEnvelope {
                block_root: block.root,
                expected_block_hash: block_hash,
            });
        }

        return None;
    }

    if block.execution_status.is_invalid() {
        return None;
    }
    block
        .execution_status
        .block_hash()
        .map(|expected_block_hash| StoredPayloadSource::PreGloasBlock {
            block_root: block.root,
            expected_block_hash,
        })
}

pub(crate) fn referenced_execution_payload_hashes<T: BeaconChainTypes>(
    fork_choice: &BeaconForkChoice<T>,
) -> HashSet<ExecutionBlockHash> {
    fork_choice
        .proto_array()
        .blocks()
        .flat_map(|block| {
            [
                block.execution_payload_parent_hash,
                block.execution_payload_block_hash,
                block.execution_status.block_hash(),
            ]
            .into_iter()
            .flatten()
        })
        .collect()
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Restore gas limits available directly from payloads retained with fork choice.
    pub(crate) fn initialize_observed_execution_payloads(&self) -> Result<(), BeaconChainError> {
        let sources = {
            let fork_choice = self.canonical_head.fork_choice_read_lock();
            fork_choice
                .proto_array()
                .blocks()
                .filter_map(|block| stored_payload_source(&block))
                .collect::<Vec<_>>()
        };

        for source in sources {
            match source {
                StoredPayloadSource::GloasGenesis {
                    block_root,
                    expected_block_hash,
                } => {
                    let Some(block) = self
                        .store
                        .get_blinded_block(&block_root)
                        .map_err(BeaconChainError::DBError)?
                    else {
                        warn!(
                            ?block_root,
                            "Unable to restore execution payload gas limit: block missing"
                        );
                        continue;
                    };
                    let bid = &block
                        .message()
                        .body()
                        .signed_execution_payload_bid()
                        .map_err(BeaconChainError::BeaconStateError)?
                        .message;
                    if bid.parent_block_hash == expected_block_hash {
                        self.observed_execution_payloads
                            .insert(bid.parent_block_hash, bid.gas_limit);
                    } else {
                        warn!(
                            ?block_root,
                            %expected_block_hash,
                            actual_block_hash = %bid.parent_block_hash,
                            "Unable to restore execution payload gas limit: block hash mismatch"
                        );
                    }
                }
                StoredPayloadSource::GloasEnvelope {
                    block_root,
                    expected_block_hash,
                } => {
                    let Some(envelope) = self
                        .store
                        .get_payload_envelope(&block_root)
                        .map_err(BeaconChainError::DBError)?
                    else {
                        warn!(
                            ?block_root,
                            "Unable to restore execution payload gas limit: envelope missing"
                        );
                        continue;
                    };
                    let payload = &envelope.message.payload;
                    if payload.block_hash == expected_block_hash {
                        self.observed_execution_payloads
                            .insert(payload.block_hash, payload.gas_limit);
                    } else {
                        warn!(
                            ?block_root,
                            %expected_block_hash,
                            actual_block_hash = %payload.block_hash,
                            "Unable to restore execution payload gas limit: envelope hash mismatch"
                        );
                    }
                }
                StoredPayloadSource::PreGloasBlock {
                    block_root,
                    expected_block_hash,
                } => {
                    let Some(block) = self
                        .store
                        .get_blinded_block(&block_root)
                        .map_err(BeaconChainError::DBError)?
                    else {
                        warn!(
                            ?block_root,
                            "Unable to restore execution payload gas limit: block missing"
                        );
                        continue;
                    };
                    let payload = block
                        .message()
                        .execution_payload()
                        .map_err(BeaconChainError::BeaconStateError)?;
                    if payload.block_hash() == expected_block_hash {
                        self.observed_execution_payloads
                            .insert(payload.block_hash(), payload.gas_limit());
                    } else {
                        warn!(
                            ?block_root,
                            %expected_block_hash,
                            actual_block_hash = %payload.block_hash(),
                            "Unable to restore execution payload gas limit: block hash mismatch"
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use types::ExecutionBlockHash;

    use super::ObservedExecutionPayloads;

    #[test]
    fn retains_only_referenced_payloads() {
        let payloads = ObservedExecutionPayloads::default();
        let retained = ExecutionBlockHash::repeat_byte(0x01);
        let pruned = ExecutionBlockHash::repeat_byte(0x02);

        payloads.insert(retained, 30_000_000);
        payloads.insert(pruned, 36_000_000);
        payloads.retain(&HashSet::from([retained]));

        assert_eq!(payloads.get_gas_limit(retained), Some(30_000_000));
        assert_eq!(payloads.get_gas_limit(pruned), None);
    }

    #[test]
    fn keeps_first_gas_limit_for_execution_block_hash() {
        let payloads = ObservedExecutionPayloads::default();
        let block_hash = ExecutionBlockHash::repeat_byte(0x01);

        payloads.insert(block_hash, 30_000_000);
        payloads.insert(block_hash, 36_000_000);

        assert_eq!(payloads.get_gas_limit(block_hash), Some(30_000_000));
    }
}

//! Provides tools for checking if a node is ready for the Bellatrix upgrade and following merge
//! transition.

use crate::{BeaconChain, BeaconChainError as Error, BeaconChainTypes};
use execution_layer::BlockByNumberQuery;
use serde::{Deserialize, Serialize, Serializer};
use slog::debug;
use std::fmt;
use std::fmt::Write;
use types::*;

/// The time before the Bellatrix fork when we will start issuing warnings about preparation.
pub const SECONDS_IN_A_WEEK: u64 = 604800;
pub const MERGE_READINESS_PREPARATION_SECONDS: u64 = SECONDS_IN_A_WEEK * 2;

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct MergeConfig {
    #[serde(serialize_with = "serialize_uint256")]
    pub terminal_total_difficulty: Option<Uint256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_block_hash: Option<ExecutionBlockHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_block_hash_epoch: Option<Epoch>,
}

impl fmt::Display for MergeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terminal_block_hash.is_none()
            && self.terminal_block_hash_epoch.is_none()
            && self.terminal_total_difficulty.is_none()
        {
            return write!(
                f,
                "Merge terminal difficulty parameters not configured, check your config"
            );
        }
        let mut display_string = String::new();
        if let Some(terminal_total_difficulty) = self.terminal_total_difficulty {
            write!(
                display_string,
                "terminal_total_difficulty: {},",
                terminal_total_difficulty
            )?;
        }
        if let Some(terminal_block_hash) = self.terminal_block_hash {
            write!(
                display_string,
                "terminal_block_hash: {},",
                terminal_block_hash
            )?;
        }
        if let Some(terminal_block_hash_epoch) = self.terminal_block_hash_epoch {
            write!(
                display_string,
                "terminal_block_hash_epoch: {},",
                terminal_block_hash_epoch
            )?;
        }
        write!(f, "{}", display_string.trim_end_matches(','))?;
        Ok(())
    }
}
impl MergeConfig {
    /// Instantiate `self` from the values in a `ChainSpec`.
    pub fn from_chainspec(spec: &ChainSpec) -> Self {
        let mut params = MergeConfig::default();
        if spec.terminal_total_difficulty != Uint256::max_value() {
            params.terminal_total_difficulty = Some(spec.terminal_total_difficulty);
        }
        if spec.terminal_block_hash != ExecutionBlockHash::zero() {
            params.terminal_block_hash = Some(spec.terminal_block_hash);
        }
        if spec.terminal_block_hash_activation_epoch != Epoch::max_value() {
            params.terminal_block_hash_epoch = Some(spec.terminal_block_hash_activation_epoch);
        }
        params
    }
}

/// Indicates if a node is ready for the Bellatrix upgrade and subsequent merge transition.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type")]
pub enum MergeReadiness {
    /// The node is ready, as far as we can tell.
    Ready {
        config: MergeConfig,
        #[serde(serialize_with = "serialize_uint256")]
        current_difficulty: Option<Uint256>,
    },
    /// The EL can be reached and has the correct configuration, however it's not yet synced.
    NotSynced,
    /// The user has not configured this node to use an execution endpoint.
    NoExecutionEndpoint,
}

impl fmt::Display for MergeReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MergeReadiness::Ready {
                config: params,
                current_difficulty,
            } => {
                write!(
                    f,
                    "This node appears ready for the merge. \
                        Params: {}, current_difficulty: {:?}",
                    params, current_difficulty
                )
            }
            MergeReadiness::NotSynced => write!(
                f,
                "The execution endpoint is connected and configured, \
                    however it is not yet synced"
            ),
            MergeReadiness::NoExecutionEndpoint => write!(
                f,
                "The --execution-endpoint flag is not specified, this is a \
                    requirement for the merge"
            ),
        }
    }
}

pub enum GenesisExecutionPayloadStatus {
    Correct(ExecutionBlockHash),
    BlockHashMismatch {
        got: ExecutionBlockHash,
        expected: ExecutionBlockHash,
    },
    TransactionsRootMismatch {
        got: Hash256,
        expected: Hash256,
    },
    WithdrawalsRootMismatch {
        got: Hash256,
        expected: Hash256,
    },
    OtherMismatch,
    Irrelevant,
    AlreadyHappened,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Returns `true` if user has an EL configured, or if the Bellatrix fork has occurred or will
    /// occur within `MERGE_READINESS_PREPARATION_SECONDS`.
    pub fn is_time_to_prepare_for_bellatrix(&self, current_slot: Slot) -> bool {
        if let Some(bellatrix_epoch) = self.spec.bellatrix_fork_epoch {
            let bellatrix_slot = bellatrix_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let merge_readiness_preparation_slots =
                MERGE_READINESS_PREPARATION_SECONDS / self.spec.seconds_per_slot;

            if self.execution_layer.is_some() {
                // The user has already configured an execution layer, start checking for readiness
                // right away.
                true
            } else {
                // Return `true` if Bellatrix has happened or is within the preparation time.
                current_slot + merge_readiness_preparation_slots > bellatrix_slot
            }
        } else {
            // The Bellatrix fork epoch has not been defined yet, no need to prepare.
            false
        }
    }

    /// Attempts to connect to the EL and confirm that it is ready for the merge.
    pub async fn check_merge_readiness(&self, current_slot: Slot) -> MergeReadiness {
        if let Some(el) = self.execution_layer.as_ref() {
            if !el.is_synced_for_notifier(current_slot).await {
                // The EL is not synced.
                return MergeReadiness::NotSynced;
            }
            let params = MergeConfig::from_chainspec(&self.spec);
            let current_difficulty = el.get_current_difficulty().await.ok();
            MergeReadiness::Ready {
                config: params,
                current_difficulty,
            }
        } else {
            // There is no EL configured.
            MergeReadiness::NoExecutionEndpoint
        }
    }

    /// Check that the execution payload embedded in the genesis state matches the EL's genesis
    /// block.
    pub async fn check_genesis_execution_payload_is_correct(
        &self,
    ) -> Result<GenesisExecutionPayloadStatus, Error> {
        let head_snapshot = self.head_snapshot();
        let genesis_state = &head_snapshot.beacon_state;

        if genesis_state.slot() != 0 {
            return Ok(GenesisExecutionPayloadStatus::AlreadyHappened);
        }

        let Ok(latest_execution_payload_header) = genesis_state.latest_execution_payload_header()
        else {
            return Ok(GenesisExecutionPayloadStatus::Irrelevant);
        };
        let fork = self.spec.fork_name_at_epoch(Epoch::new(0));

        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?;
        let exec_block_hash = latest_execution_payload_header.block_hash();

        // Use getBlockByNumber(0) to check that the block hash matches.
        // At present, Geth does not respond to engine_getPayloadBodiesByRange before genesis.
        let execution_block = execution_layer
            .get_block_by_number(BlockByNumberQuery::Tag("0x0"))
            .await
            .map_err(|e| Error::ExecutionLayerGetBlockByNumberFailed(Box::new(e)))?
            .ok_or(Error::BlockHashMissingFromExecutionLayer(exec_block_hash))?;

        if execution_block.block_hash != exec_block_hash {
            return Ok(GenesisExecutionPayloadStatus::BlockHashMismatch {
                got: execution_block.block_hash,
                expected: exec_block_hash,
            });
        }

        // Double-check the block by reconstructing it.
        let execution_payload = execution_layer
            .get_payload_by_hash_legacy(exec_block_hash, fork)
            .await
            .map_err(|e| Error::ExecutionLayerGetBlockByHashFailed(Box::new(e)))?
            .ok_or(Error::BlockHashMissingFromExecutionLayer(exec_block_hash))?;

        // Verify payload integrity.
        let header_from_payload = ExecutionPayloadHeader::from(execution_payload.to_ref());

        let got_transactions_root = header_from_payload.transactions_root();
        let expected_transactions_root = latest_execution_payload_header.transactions_root();
        let got_withdrawals_root = header_from_payload.withdrawals_root().ok();
        let expected_withdrawals_root = latest_execution_payload_header.withdrawals_root().ok();

        if got_transactions_root != expected_transactions_root {
            return Ok(GenesisExecutionPayloadStatus::TransactionsRootMismatch {
                got: got_transactions_root,
                expected: expected_transactions_root,
            });
        }

        if let Some(&expected) = expected_withdrawals_root {
            if let Some(&got) = got_withdrawals_root {
                if got != expected {
                    return Ok(GenesisExecutionPayloadStatus::WithdrawalsRootMismatch {
                        got,
                        expected,
                    });
                }
            }
        }

        if header_from_payload.to_ref() != latest_execution_payload_header {
            debug!(
                self.log,
                "Genesis execution payload reconstruction failure";
                "consensus_node_header" => ?latest_execution_payload_header,
                "execution_node_header" => ?header_from_payload
            );
            return Ok(GenesisExecutionPayloadStatus::OtherMismatch);
        }

        Ok(GenesisExecutionPayloadStatus::Correct(exec_block_hash))
    }
}

/// Utility function to serialize a Uint256 as a decimal string.
fn serialize_uint256<S>(val: &Option<Uint256>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match val {
        Some(v) => v.to_string().serialize(s),
        None => s.serialize_none(),
    }
}

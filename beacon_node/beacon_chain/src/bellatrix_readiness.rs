//! Provides tools for checking genesis execution payload consistency.

use crate::{BeaconChain, BeaconChainError as Error, BeaconChainTypes};
use execution_layer::BlockByNumberQuery;
use types::*;

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

        Ok(GenesisExecutionPayloadStatus::Correct(exec_block_hash))
    }
}

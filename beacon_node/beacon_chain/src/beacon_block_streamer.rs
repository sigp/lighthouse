use crate::early_attester_cache::EarlyAttesterCache;
use crate::{BeaconChainError as Error, BeaconChainTypes, BeaconStore};
use execution_layer::ExecutionLayer;
use slog::{debug, Logger};
use std::sync::Arc;
use store::DatabaseBlock;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};
use types::{ChainSpec, ExecPayload, FullPayload, Hash256, SignedBeaconBlock};

type BlockResult<E> = Result<Option<Arc<SignedBeaconBlock<E>>>, Error>;

pub struct BeaconBlockStreamer<T: BeaconChainTypes> {
    execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    early_attester_cache: Option<EarlyAttesterCache<T::EthSpec>>,
    store: BeaconStore<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconBlockStreamer<T> {
    pub fn new(
        execution_layer: Option<ExecutionLayer<T::EthSpec>>,
        store: BeaconStore<T>,
        early_attester_cache: Option<EarlyAttesterCache<T::EthSpec>>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self {
            execution_layer,
            store,
            early_attester_cache,
            spec,
            log,
        }
    }

    async fn get_block(&self, block_root: &Hash256) -> BlockResult<T::EthSpec> {
        if let Some(block) = self
            .early_attester_cache
            .as_ref()
            .and_then(|cache| cache.get_block(*block_root))
        {
            return Ok(Some(block));
        }

        // Load block from database, returning immediately if we have the full block w payload
        // stored.
        let blinded_block = match self.store.try_get_full_block(block_root)? {
            Some(DatabaseBlock::Full(block)) => return Ok(Some(Arc::new(block))),
            Some(DatabaseBlock::Blinded(block)) => block,
            None => return Ok(None),
        };
        let fork = blinded_block.fork_name(&self.spec)?;

        // If we only have a blinded block, load the execution payload from the EL.
        let block_message = blinded_block.message();
        let execution_payload_header = block_message
            .execution_payload()
            .map_err(|_| Error::BlockVariantLacksExecutionPayload(*block_root))?
            .to_execution_payload_header();

        let exec_block_hash = execution_payload_header.block_hash();

        let execution_payload = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?
            .get_payload_by_block_hash(exec_block_hash, fork)
            .await
            .map_err(|e| {
                Error::ExecutionLayerErrorPayloadReconstruction(exec_block_hash, Box::new(e))
            })?
            .ok_or(Error::BlockHashMissingFromExecutionLayer(exec_block_hash))?;

        //FIXME(sean) avoid the clone by comparing refs to headers (`as_execution_payload_header` method ?)
        let full_payload: FullPayload<T::EthSpec> = execution_payload.clone().into();

        // Verify payload integrity.
        let header_from_payload = full_payload.to_execution_payload_header();
        if header_from_payload != execution_payload_header {
            for txn in execution_payload.transactions() {
                debug!(
                    self.log,
                    "Reconstructed txn";
                    "bytes" => format!("0x{}", hex::encode(&**txn)),
                );
            }

            return Err(Error::InconsistentPayloadReconstructed {
                slot: blinded_block.slot(),
                exec_block_hash,
                canonical_transactions_root: execution_payload_header.transactions_root(),
                reconstructed_transactions_root: header_from_payload.transactions_root(),
            });
        }

        // Add the payload to the block to form a full block.
        blinded_block
            .try_into_full_block(Some(execution_payload))
            .ok_or(Error::AddPayloadLogicError)
            .map(Arc::new)
            .map(Some)
    }

    pub fn stream(
        self,
        block_roots: Vec<Hash256>,
        executor: &TaskExecutor,
    ) -> impl Stream<Item = (Hash256, BlockResult<T::EthSpec>)> {
        let (block_tx, block_rx) = mpsc::unbounded_channel();

        executor.spawn(
            async move {
                for root in block_roots {
                    let block = self.get_block(&root).await;
                    if let Err(_) = block_tx.send((root, block)) {
                        break;
                    }
                }
            },
            "get_blocks_sender",
        );

        UnboundedReceiverStream::new(block_rx)
    }
}

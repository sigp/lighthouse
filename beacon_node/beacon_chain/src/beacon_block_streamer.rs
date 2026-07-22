use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockProcessStatus, metrics};
use execution_layer::{ExecutionLayer, ExecutionPayloadBodyV1};
use std::sync::Arc;
use store::{DatabaseBlock, ExecutionPayloadDeneb};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::{Stream, wrappers::UnboundedReceiverStream};
use tracing::{debug, error};
use types::{
    ChainSpec, EthSpec, ExecPayload, ExecutionBlockHash, ForkName, Hash256, SignedBeaconBlock,
    SignedBlindedBeaconBlock,
};
use types::{
    ExecutionPayload, ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadElectra,
    ExecutionPayloadFulu, ExecutionPayloadGloas, ExecutionPayloadHeader,
};

#[derive(PartialEq)]
pub enum CheckCaches {
    Yes,
    No,
}

#[derive(Debug)]
pub enum Error {
    PayloadReconstruction(String),
    BlocksByHashFailure(Box<execution_layer::Error>),
    InvalidPayloadBodiesResponse { expected: usize, received: usize },
}

/// The engine API only requires execution layers to support payload body requests for at least
/// 32 blocks, so larger requests are split into chunks of this size.
const MAX_PAYLOAD_BODIES_PER_REQUEST: usize = 32;

/// A block loaded from the caches or database, which is either complete or requires its
/// execution payload to be fetched from the execution layer.
enum LoadedBlock<E: EthSpec> {
    Complete(BlockResult<E>),
    NeedsPayload(BlockParts<E>),
}

type BlockResult<E> = Result<Option<Arc<SignedBeaconBlock<E>>>, BeaconChainError>;

// stores the components of a block for future re-construction in a small form
struct BlockParts<E: EthSpec> {
    blinded_block: Box<SignedBlindedBeaconBlock<E>>,
    header: Box<ExecutionPayloadHeader<E>>,
}

impl<E: EthSpec> BlockParts<E> {
    pub fn new(
        blinded: Box<SignedBlindedBeaconBlock<E>>,
        header: ExecutionPayloadHeader<E>,
    ) -> Self {
        Self {
            blinded_block: blinded,
            header: Box::new(header),
        }
    }

    pub fn root(&self) -> Hash256 {
        self.blinded_block.canonical_root()
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.header.block_hash()
    }
}

fn reconstruct_default_header_block<E: EthSpec>(
    blinded_block: Box<SignedBlindedBeaconBlock<E>>,
    header_from_block: ExecutionPayloadHeader<E>,
    spec: &ChainSpec,
) -> BlockResult<E> {
    let fork = blinded_block
        .fork_name(spec)
        .map_err(BeaconChainError::InconsistentFork)?;

    let payload: ExecutionPayload<E> = match fork {
        ForkName::Bellatrix => ExecutionPayloadBellatrix::default().into(),
        ForkName::Capella => ExecutionPayloadCapella::default().into(),
        ForkName::Deneb => ExecutionPayloadDeneb::default().into(),
        ForkName::Electra => ExecutionPayloadElectra::default().into(),
        ForkName::Fulu => ExecutionPayloadFulu::default().into(),
        ForkName::Gloas => ExecutionPayloadGloas::default().into(),
        ForkName::Base | ForkName::Altair => {
            return Err(Error::PayloadReconstruction(format!(
                "Block with fork variant {} has execution payload",
                fork
            ))
            .into());
        }
    };

    let header_from_payload = ExecutionPayloadHeader::from(payload.to_ref());
    if header_from_payload == header_from_block {
        blinded_block
            .try_into_full_block(Some(payload))
            .ok_or(BeaconChainError::AddPayloadLogicError)
            .map(Arc::new)
            .map(Some)
    } else {
        Err(BeaconChainError::InconsistentPayloadReconstructed {
            slot: blinded_block.slot(),
            exec_block_hash: header_from_block.block_hash(),
            canonical_transactions_root: header_from_block.transactions_root(),
            reconstructed_transactions_root: header_from_payload.transactions_root(),
        })
    }
}

fn reconstruct_block<E: EthSpec>(
    block_parts: BlockParts<E>,
    payload_body: Option<ExecutionPayloadBodyV1<E>>,
) -> BlockResult<E> {
    let Some(payload_body) = payload_body else {
        return Err(BeaconChainError::BlockHashMissingFromExecutionLayer(
            block_parts.block_hash(),
        ));
    };

    match payload_body.to_payload(block_parts.header.as_ref().clone()) {
        Ok(payload) => {
            let header_from_payload = ExecutionPayloadHeader::from(payload.to_ref());
            if header_from_payload == *block_parts.header {
                block_parts
                    .blinded_block
                    .try_into_full_block(Some(payload))
                    .ok_or(BeaconChainError::AddPayloadLogicError)
                    .map(Arc::new)
                    .map(Some)
            } else {
                let error = BeaconChainError::InconsistentPayloadReconstructed {
                    slot: block_parts.blinded_block.slot(),
                    exec_block_hash: block_parts.header.block_hash(),
                    canonical_transactions_root: block_parts.header.transactions_root(),
                    reconstructed_transactions_root: header_from_payload.transactions_root(),
                };
                debug!(root = ?block_parts.root(), ?error, "Failed to reconstruct block");
                Err(error)
            }
        }
        Err(string) => Err(Error::PayloadReconstruction(string).into()),
    }
}

pub struct BeaconBlockStreamer<T: BeaconChainTypes> {
    execution_layer: ExecutionLayer<T::EthSpec>,
    check_caches: CheckCaches,
    beacon_chain: Arc<BeaconChain<T>>,
}

impl<T: BeaconChainTypes> BeaconBlockStreamer<T> {
    pub fn new(
        beacon_chain: &Arc<BeaconChain<T>>,
        check_caches: CheckCaches,
    ) -> Result<Arc<Self>, BeaconChainError> {
        let execution_layer = beacon_chain
            .execution_layer
            .as_ref()
            .ok_or(BeaconChainError::ExecutionLayerMissing)?
            .clone();

        Ok(Arc::new(Self {
            execution_layer,
            check_caches,
            beacon_chain: beacon_chain.clone(),
        }))
    }

    fn check_caches(&self, root: Hash256) -> Option<Arc<SignedBeaconBlock<T::EthSpec>>> {
        if self.check_caches == CheckCaches::Yes {
            match self.beacon_chain.get_block_process_status(&root) {
                BlockProcessStatus::Unknown => None,
                BlockProcessStatus::NotValidated(block, _)
                | BlockProcessStatus::ExecutionValidated(block) => {
                    metrics::inc_counter(&metrics::BEACON_REQRESP_PRE_IMPORT_CACHE_HITS);
                    Some(block)
                }
            }
        } else {
            None
        }
    }

    /// Load a block from the caches or the database. Blinded blocks with a non-default payload
    /// header are returned as `NeedsPayload` for reconstruction via the execution layer.
    fn load_block(&self, root: Hash256) -> LoadedBlock<T::EthSpec> {
        if let Some(cached_block) = self.check_caches(root) {
            return LoadedBlock::Complete(Ok(Some(cached_block)));
        }

        match self.beacon_chain.store.try_get_full_block(&root) {
            Err(e) => LoadedBlock::Complete(Err(e.into())),
            Ok(None) => LoadedBlock::Complete(Ok(None)),
            Ok(Some(DatabaseBlock::Full(block))) => {
                LoadedBlock::Complete(Ok(Some(Arc::new(block))))
            }
            Ok(Some(DatabaseBlock::Blinded(block))) => {
                match block
                    .message()
                    .execution_payload()
                    .map(|payload| payload.to_execution_payload_header())
                {
                    Err(e) => LoadedBlock::Complete(Err(BeaconChainError::BeaconStateError(e))),
                    Ok(header) => {
                        if header.block_hash() == ExecutionBlockHash::zero() {
                            LoadedBlock::Complete(reconstruct_default_header_block(
                                Box::new(block),
                                header,
                                &self.beacon_chain.spec,
                            ))
                        } else {
                            LoadedBlock::NeedsPayload(BlockParts::new(Box::new(block), header))
                        }
                    }
                }
            }
        }
    }

    /// Fetch payload bodies for `block_hashes` from the execution layer.
    ///
    /// The returned vec has the same length and order as `block_hashes`. A body the execution
    /// layer doesn't know about is `None`.
    async fn fetch_payload_bodies(
        &self,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<T::EthSpec>>>, Error> {
        let mut bodies = Vec::with_capacity(block_hashes.len());
        for chunk in block_hashes.chunks(MAX_PAYLOAD_BODIES_PER_REQUEST) {
            let chunk_bodies = self
                .execution_layer
                .get_payload_bodies_by_hash(chunk.to_vec())
                .await
                .map_err(|e| Error::BlocksByHashFailure(Box::new(e)))?;

            if chunk_bodies.len() != chunk.len() {
                return Err(Error::InvalidPayloadBodiesResponse {
                    expected: chunk.len(),
                    received: chunk_bodies.len(),
                });
            }
            bodies.extend(chunk_bodies);
        }
        Ok(bodies)
    }

    // used when the execution engine doesn't support the payload bodies methods
    async fn stream_blocks_fallback(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        debug!("Using slower fallback method of eth_getBlockByHash()");
        for root in block_roots {
            let cached_block = self.check_caches(root);
            let block_result = if cached_block.is_some() {
                Ok(cached_block)
            } else {
                self.beacon_chain
                    .get_block(&root)
                    .await
                    .map(|opt_block| opt_block.map(Arc::new))
            };

            if sender.send((root, Arc::new(block_result))).is_err() {
                break;
            }
        }
    }

    async fn stream_blocks(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        let n_roots = block_roots.len();

        let streamer = self.clone();
        // Loading from the DB is slow -> spawn a blocking task
        let loaded_blocks = match self
            .beacon_chain
            .spawn_blocking_handle(
                move || {
                    block_roots
                        .into_iter()
                        .map(|root| (root, streamer.load_block(root)))
                        .collect::<Vec<_>>()
                },
                "load_beacon_blocks",
            )
            .await
        {
            Ok(loaded_blocks) => loaded_blocks,
            Err(e) => {
                error!(
                    error = ?e,
                    "BeaconBlockStreamer: Failed to load blocks"
                );
                return;
            }
        };

        let block_hashes = loaded_blocks
            .iter()
            .filter_map(|(_, loaded)| match loaded {
                LoadedBlock::NeedsPayload(block_parts) => Some(block_parts.block_hash()),
                LoadedBlock::Complete(_) => None,
            })
            .collect::<Vec<_>>();
        // On failure, complete blocks are still sent and each block requiring a payload gets
        // the (shared) error as its result, so that the stream terminates with an error
        // rather than looking like a complete response.
        let mut bodies = match self.fetch_payload_bodies(block_hashes).await {
            Ok(bodies) => Ok(bodies.into_iter()),
            Err(e) => {
                let block_result: Arc<BlockResult<T::EthSpec>> = Arc::new(Err(e.into()));
                debug!(error = ?block_result, "Payload bodies by hash failure");
                Err(block_result)
            }
        };

        let mut n_sent = 0usize;
        let mut n_success = 0usize;
        for (root, loaded) in loaded_blocks {
            let result = match loaded {
                LoadedBlock::Complete(block_result) => Arc::new(block_result),
                // `bodies` has one entry per `NeedsPayload` block, in order.
                LoadedBlock::NeedsPayload(block_parts) => match &mut bodies {
                    Ok(bodies) => Arc::new(reconstruct_block(block_parts, bodies.next().flatten())),
                    Err(block_result) => block_result.clone(),
                },
            };

            let successful = result
                .as_ref()
                .as_ref()
                .map(|opt| opt.is_some())
                .unwrap_or(false);

            if sender.send((root, result)).is_err() {
                break;
            } else {
                n_sent += 1;
                if successful {
                    n_success += 1;
                }
            }
        }

        debug!(
            requested_blocks = n_roots,
            sent = n_sent,
            succeeded = n_success,
            failed = (n_sent - n_success),
            "BeaconBlockStreamer finished"
        );
    }

    pub async fn stream(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        match self.execution_layer.get_engine_capabilities(None).await {
            Ok(capabilities) if capabilities.get_payload_bodies_by_hash_v1 => {
                self.stream_blocks(block_roots, sender).await;
            }
            Ok(_) => {
                // use the fallback method
                self.stream_blocks_fallback(block_roots, sender).await;
            }
            Err(e) => {
                let error = BeaconChainError::EngineGetCapabilititesFailed(Box::new(e));
                send_errors(block_roots, sender, error);
            }
        }
    }

    pub fn launch_stream(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
    ) -> impl Stream<Item = (Hash256, Arc<BlockResult<T::EthSpec>>)> {
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        debug!(
            blocks = block_roots.len(),
            "Launching a BeaconBlockStreamer"
        );
        let executor = self.beacon_chain.task_executor.clone();
        executor.spawn(self.stream(block_roots, block_tx), "get_blocks_sender");
        UnboundedReceiverStream::new(block_rx)
    }
}

fn send_errors<E: EthSpec>(
    block_roots: Vec<Hash256>,
    sender: UnboundedSender<(Hash256, Arc<BlockResult<E>>)>,
    beacon_chain_error: BeaconChainError,
) {
    let result = Arc::new(Err(beacon_chain_error));
    for root in block_roots {
        if sender.send((root, result.clone())).is_err() {
            break;
        }
    }
}

impl From<Error> for BeaconChainError {
    fn from(value: Error) -> Self {
        BeaconChainError::BlockStreamerError(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::beacon_block_streamer::{BeaconBlockStreamer, CheckCaches};
    use crate::test_utils::{BeaconChainHarness, EphemeralHarnessType, test_spec};
    use bls::Keypair;
    use fixed_bytes::FixedBytesExtended;
    use std::sync::Arc;
    use std::sync::LazyLock;
    use tokio::sync::mpsc;
    use types::{ChainSpec, Epoch, EthSpec, Hash256, MinimalEthSpec, Slot};

    const VALIDATOR_COUNT: usize = 48;

    /// A cached set of keys.
    static KEYPAIRS: LazyLock<Vec<Keypair>> =
        LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

    fn get_harness(
        validator_count: usize,
        spec: Arc<ChainSpec>,
    ) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .spec(spec)
            .keypairs(KEYPAIRS[0..validator_count].to_vec())
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();

        harness
    }

    // TODO(EIP-7732) Extend this test for gloas
    #[tokio::test]
    async fn check_all_blocks_from_altair_to_fulu() {
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch() as usize;
        let num_epochs = 12;
        let bellatrix_fork_epoch = 0usize;
        let capella_fork_epoch = 4usize;
        let deneb_fork_epoch = 6usize;
        let electra_fork_epoch = 8usize;
        let fulu_fork_epoch = 10usize;
        let num_blocks_produced = num_epochs * slots_per_epoch;

        let mut spec = test_spec::<MinimalEthSpec>();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(bellatrix_fork_epoch as u64));
        spec.capella_fork_epoch = Some(Epoch::new(capella_fork_epoch as u64));
        spec.deneb_fork_epoch = Some(Epoch::new(deneb_fork_epoch as u64));
        spec.electra_fork_epoch = Some(Epoch::new(electra_fork_epoch as u64));
        spec.fulu_fork_epoch = Some(Epoch::new(fulu_fork_epoch as u64));
        spec.gloas_fork_epoch = None;
        let spec = Arc::new(spec);

        let harness = get_harness(VALIDATOR_COUNT, spec.clone());
        // finish rest of epochs
        harness.extend_slots(num_epochs * slots_per_epoch).await;

        let head = harness.chain.head_snapshot();
        let state = &head.beacon_state;

        assert_eq!(
            state.slot(),
            Slot::new(num_blocks_produced as u64),
            "head should be at the current slot"
        );
        assert_eq!(
            state.current_epoch(),
            num_blocks_produced as u64 / MinimalEthSpec::slots_per_epoch(),
            "head should be at the expected epoch"
        );
        assert_eq!(
            state.current_justified_checkpoint().epoch,
            state.current_epoch() - 1,
            "the head should be justified one behind the current epoch"
        );
        assert_eq!(
            state.finalized_checkpoint().epoch,
            state.current_epoch() - 2,
            "the head should be finalized two behind the current epoch"
        );

        let block_roots: Vec<Hash256> = harness
            .chain
            .forwards_iter_block_roots(Slot::new(0))
            .expect("should get iter")
            .map(Result::unwrap)
            .map(|(root, _)| root)
            .collect();

        let mut expected_blocks = vec![];
        // get all blocks the old fashioned way
        for root in &block_roots {
            let block = harness
                .chain
                .get_block(root)
                .await
                .expect("should get block")
                .expect("block should exist");
            expected_blocks.push(block);
        }

        for epoch in 0..num_epochs {
            let start = epoch * slots_per_epoch;
            let mut epoch_roots = vec![Hash256::zero(); slots_per_epoch];
            epoch_roots[..].clone_from_slice(&block_roots[start..(start + slots_per_epoch)]);
            let streamer = BeaconBlockStreamer::new(&harness.chain, CheckCaches::No)
                .expect("should create streamer");
            let (block_tx, mut block_rx) = mpsc::unbounded_channel();
            streamer.stream(epoch_roots.clone(), block_tx).await;

            for (i, expected_root) in epoch_roots.into_iter().enumerate() {
                let (found_root, found_block_result) =
                    block_rx.recv().await.expect("should get block");

                assert_eq!(
                    found_root, expected_root,
                    "expected block root should match"
                );
                match found_block_result.as_ref() {
                    Ok(maybe_block) => {
                        let found_block = maybe_block.clone().expect("should have a block");
                        let expected_block = expected_blocks
                            .get(start + i)
                            .expect("should get expected block");
                        assert_eq!(
                            found_block.as_ref(),
                            expected_block,
                            "expected block should match found block"
                        );
                    }
                    Err(e) => panic!("Error retrieving block {}: {:?}", expected_root, e),
                }
            }
        }
    }
}

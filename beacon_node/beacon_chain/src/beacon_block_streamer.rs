use crate::{metrics, BeaconChain, BeaconChainError, BeaconChainTypes, BlockProcessStatus};
use execution_layer::{ExecutionLayer, ExecutionPayloadBodyV1};
use slog::{crit, debug, error, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use store::{DatabaseBlock, ExecutionPayloadDeneb};
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};
use types::{
    ChainSpec, EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayloadEIP7732, ForkName,
    Hash256, SignedBeaconBlock, SignedBlindedBeaconBlock, Slot,
};
use types::{
    ExecutionPayload, ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadElectra,
    ExecutionPayloadHeader,
};

#[derive(PartialEq)]
pub enum CheckCaches {
    Yes,
    No,
}

#[derive(Debug)]
pub enum Error {
    PayloadReconstruction(String),
    BlocksByRangeFailure(Box<execution_layer::Error>),
    RequestNotFound,
    BlockResultNotFound,
}

const BLOCKS_PER_RANGE_REQUEST: u64 = 32;

// This is the same as a DatabaseBlock but the Arc allows us to avoid an unnecessary clone.
enum LoadedBeaconBlock<E: EthSpec> {
    Full(Arc<SignedBeaconBlock<E>>),
    Blinded(Box<SignedBlindedBeaconBlock<E>>),
}
type LoadResult<E> = Result<Option<LoadedBeaconBlock<E>>, BeaconChainError>;
type BlockResult<E> = Result<Option<Arc<SignedBeaconBlock<E>>>, BeaconChainError>;

enum RequestState<E: EthSpec> {
    UnSent(Vec<BlockParts<E>>),
    Sent(HashMap<Hash256, Arc<BlockResult<E>>>),
}

struct BodiesByRange<E: EthSpec> {
    start: u64,
    count: u64,
    state: RequestState<E>,
}

// stores the components of a block for future re-construction in a small form
struct BlockParts<E: EthSpec> {
    blinded_block: Box<SignedBlindedBeaconBlock<E>>,
    header: Box<ExecutionPayloadHeader<E>>,
    body: Option<Box<ExecutionPayloadBodyV1<E>>>,
}

impl<E: EthSpec> BlockParts<E> {
    pub fn new(
        blinded: Box<SignedBlindedBeaconBlock<E>>,
        header: ExecutionPayloadHeader<E>,
    ) -> Self {
        Self {
            blinded_block: blinded,
            header: Box::new(header),
            body: None,
        }
    }

    pub fn root(&self) -> Hash256 {
        self.blinded_block.canonical_root()
    }

    pub fn slot(&self) -> Slot {
        self.blinded_block.message().slot()
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
        ForkName::EIP7732 => ExecutionPayloadEIP7732::default().into(),
        ForkName::Base | ForkName::Altair => {
            return Err(Error::PayloadReconstruction(format!(
                "Block with fork variant {} has execution payload",
                fork
            ))
            .into())
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

fn reconstruct_blocks<E: EthSpec>(
    block_map: &mut HashMap<Hash256, Arc<BlockResult<E>>>,
    block_parts_with_bodies: HashMap<Hash256, BlockParts<E>>,
    log: &Logger,
) {
    for (root, block_parts) in block_parts_with_bodies {
        if let Some(payload_body) = block_parts.body {
            match payload_body.to_payload(block_parts.header.as_ref().clone()) {
                Ok(payload) => {
                    let header_from_payload = ExecutionPayloadHeader::from(payload.to_ref());
                    if header_from_payload == *block_parts.header {
                        block_map.insert(
                            root,
                            Arc::new(
                                block_parts
                                    .blinded_block
                                    .try_into_full_block(Some(payload))
                                    .ok_or(BeaconChainError::AddPayloadLogicError)
                                    .map(Arc::new)
                                    .map(Some),
                            ),
                        );
                    } else {
                        let error = BeaconChainError::InconsistentPayloadReconstructed {
                            slot: block_parts.blinded_block.slot(),
                            exec_block_hash: block_parts.header.block_hash(),
                            canonical_transactions_root: block_parts.header.transactions_root(),
                            reconstructed_transactions_root: header_from_payload
                                .transactions_root(),
                        };
                        debug!(log, "Failed to reconstruct block"; "root" => ?root, "error" => ?error);
                        block_map.insert(root, Arc::new(Err(error)));
                    }
                }
                Err(string) => {
                    block_map.insert(
                        root,
                        Arc::new(Err(Error::PayloadReconstruction(string).into())),
                    );
                }
            }
        } else {
            block_map.insert(
                root,
                Arc::new(Err(BeaconChainError::BlockHashMissingFromExecutionLayer(
                    block_parts.block_hash(),
                ))),
            );
        }
    }
}

impl<E: EthSpec> BodiesByRange<E> {
    pub fn new(maybe_block_parts: Option<BlockParts<E>>) -> Self {
        if let Some(block_parts) = maybe_block_parts {
            Self {
                start: block_parts.header.block_number(),
                count: 1,
                state: RequestState::UnSent(vec![block_parts]),
            }
        } else {
            Self {
                start: 0,
                count: 0,
                state: RequestState::UnSent(vec![]),
            }
        }
    }

    pub fn is_unsent(&self) -> bool {
        matches!(self.state, RequestState::UnSent(_))
    }

    pub fn push_block_parts(&mut self, block_parts: BlockParts<E>) -> Result<(), BlockParts<E>> {
        if self.count == BLOCKS_PER_RANGE_REQUEST {
            return Err(block_parts);
        }

        match &mut self.state {
            RequestState::Sent(_) => Err(block_parts),
            RequestState::UnSent(blocks_parts_vec) => {
                let block_number = block_parts.header.block_number();
                if self.count == 0 {
                    self.start = block_number;
                    self.count = 1;
                    blocks_parts_vec.push(block_parts);
                    Ok(())
                } else {
                    // need to figure out if this block fits in the request
                    if block_number < self.start
                        || self.start + BLOCKS_PER_RANGE_REQUEST <= block_number
                    {
                        return Err(block_parts);
                    }

                    blocks_parts_vec.push(block_parts);
                    if self.start + self.count <= block_number {
                        self.count = block_number - self.start + 1;
                    }

                    Ok(())
                }
            }
        }
    }

    async fn execute(&mut self, execution_layer: &ExecutionLayer<E>, log: &Logger) {
        if let RequestState::UnSent(blocks_parts_ref) = &mut self.state {
            let block_parts_vec = std::mem::take(blocks_parts_ref);

            let mut block_map = HashMap::new();
            match execution_layer
                .get_payload_bodies_by_range(self.start, self.count)
                .await
            {
                Ok(bodies) => {
                    let mut range_map = (self.start..(self.start + self.count))
                        .zip(bodies.into_iter().chain(std::iter::repeat(None)))
                        .collect::<HashMap<_, _>>();

                    let mut with_bodies = HashMap::new();
                    for mut block_parts in block_parts_vec {
                        with_bodies
                            // it's possible the same block is requested twice, using
                            // or_insert_with() skips duplicates
                            .entry(block_parts.root())
                            .or_insert_with(|| {
                                let block_number = block_parts.header.block_number();
                                block_parts.body =
                                    range_map.remove(&block_number).flatten().map(Box::new);

                                block_parts
                            });
                    }

                    reconstruct_blocks(&mut block_map, with_bodies, log);
                }
                Err(e) => {
                    let block_result =
                        Arc::new(Err(Error::BlocksByRangeFailure(Box::new(e)).into()));
                    debug!(log, "Payload bodies by range failure"; "error" => ?block_result);
                    for block_parts in block_parts_vec {
                        block_map.insert(block_parts.root(), block_result.clone());
                    }
                }
            }
            self.state = RequestState::Sent(block_map);
        }
    }

    pub async fn get_block_result(
        &mut self,
        root: &Hash256,
        execution_layer: &ExecutionLayer<E>,
        log: &Logger,
    ) -> Option<Arc<BlockResult<E>>> {
        self.execute(execution_layer, log).await;
        if let RequestState::Sent(map) = &self.state {
            return map.get(root).cloned();
        }
        // Shouldn't reach this point
        None
    }
}

#[derive(Clone)]
enum EngineRequest<E: EthSpec> {
    ByRange(Arc<RwLock<BodiesByRange<E>>>),
    // When we already have the data or there's an error
    NoRequest(Arc<RwLock<HashMap<Hash256, Arc<BlockResult<E>>>>>),
}

impl<E: EthSpec> EngineRequest<E> {
    pub fn new_by_range() -> Self {
        Self::ByRange(Arc::new(RwLock::new(BodiesByRange::new(None))))
    }
    pub fn new_no_request() -> Self {
        Self::NoRequest(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn is_unsent(&self) -> bool {
        match self {
            Self::ByRange(bodies_by_range) => bodies_by_range.read().await.is_unsent(),
            Self::NoRequest(_) => false,
        }
    }

    pub async fn push_block_parts(&mut self, block_parts: BlockParts<E>, log: &Logger) {
        match self {
            Self::ByRange(bodies_by_range) => {
                let mut request = bodies_by_range.write().await;

                if let Err(block_parts) = request.push_block_parts(block_parts) {
                    drop(request);
                    let new_by_range = BodiesByRange::new(Some(block_parts));
                    *self = Self::ByRange(Arc::new(RwLock::new(new_by_range)));
                }
            }
            Self::NoRequest(_) => {
                // this should _never_ happen
                crit!(
                    log,
                    "Please notify the devs";
                    "beacon_block_streamer" => "push_block_parts called on NoRequest Variant",
                );
            }
        }
    }

    pub async fn push_block_result(
        &mut self,
        root: Hash256,
        block_result: BlockResult<E>,
        log: &Logger,
    ) {
        // this function will only fail if something is seriously wrong
        match self {
            Self::ByRange(_) => {
                // this should _never_ happen
                crit!(
                    log,
                    "Please notify the devs";
                    "beacon_block_streamer" => "push_block_result called on ByRange",
                );
            }
            Self::NoRequest(results) => {
                results.write().await.insert(root, Arc::new(block_result));
            }
        }
    }

    pub async fn get_block_result(
        &self,
        root: &Hash256,
        execution_layer: &ExecutionLayer<E>,
        log: &Logger,
    ) -> Arc<BlockResult<E>> {
        match self {
            Self::ByRange(by_range) => {
                by_range
                    .write()
                    .await
                    .get_block_result(root, execution_layer, log)
                    .await
            }
            Self::NoRequest(map) => map.read().await.get(root).cloned(),
        }
        .unwrap_or_else(|| {
            crit!(
                log,
                "Please notify the devs";
                "beacon_block_streamer" => "block_result not found in request",
                "root" => ?root,
            );
            Arc::new(Err(Error::BlockResultNotFound.into()))
        })
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
                BlockProcessStatus::NotValidated(block)
                | BlockProcessStatus::ExecutionValidated(block) => {
                    metrics::inc_counter(&metrics::BEACON_REQRESP_PRE_IMPORT_CACHE_HITS);
                    Some(block)
                }
            }
        } else {
            None
        }
    }

    async fn load_payloads(
        self: &Arc<Self>,
        block_roots: Vec<Hash256>,
    ) -> Result<Vec<(Hash256, LoadResult<T::EthSpec>)>, BeaconChainError> {
        let streamer = self.clone();
        // Loading from the DB is slow -> spawn a blocking task
        self.beacon_chain
            .spawn_blocking_handle(
                move || {
                    let mut db_blocks = Vec::new();
                    for root in block_roots {
                        if let Some(cached_block) =
                            streamer.check_caches(root).map(LoadedBeaconBlock::Full)
                        {
                            db_blocks.push((root, Ok(Some(cached_block))));
                            continue;
                        }

                        match streamer.beacon_chain.store.try_get_full_block(&root) {
                            Err(e) => db_blocks.push((root, Err(e.into()))),
                            Ok(opt_block) => db_blocks.push((
                                root,
                                Ok(opt_block.map(|db_block| match db_block {
                                    DatabaseBlock::Full(block) => {
                                        LoadedBeaconBlock::Full(Arc::new(block))
                                    }
                                    DatabaseBlock::Blinded(block) => {
                                        LoadedBeaconBlock::Blinded(Box::new(block))
                                    }
                                })),
                            )),
                        }
                    }
                    db_blocks
                },
                "load_beacon_blocks",
            )
            .await
    }

    /// Pre-process the loaded blocks into execution engine requests.
    ///
    /// The purpose of this function is to separate the blocks into 2 categories:
    /// 1) no_request - when we already have the full block or there's an error
    /// 2) blocks_by_range - used for blinded blocks
    ///
    /// The function returns a vector of block roots in the same order as requested
    /// along with the engine request that each root corresponds to.
    async fn get_requests(
        &self,
        payloads: Vec<(Hash256, LoadResult<T::EthSpec>)>,
    ) -> Vec<(Hash256, EngineRequest<T::EthSpec>)> {
        let mut ordered_block_roots = Vec::new();
        let mut requests = HashMap::new();

        // we sort the by range blocks by slot before adding them to the
        // request as it should *better* optimize the number of blocks that
        // can fit in the same request
        let mut by_range_blocks: Vec<BlockParts<T::EthSpec>> = vec![];
        let mut no_request = EngineRequest::new_no_request();

        for (root, load_result) in payloads {
            // preserve the order of the requested blocks
            ordered_block_roots.push(root);

            let block_result = match load_result {
                Err(e) => Err(e),
                Ok(None) => Ok(None),
                Ok(Some(LoadedBeaconBlock::Full(full_block))) => Ok(Some(full_block)),
                Ok(Some(LoadedBeaconBlock::Blinded(blinded_block))) => {
                    match blinded_block
                        .message()
                        .execution_payload()
                        .map(|payload| payload.to_execution_payload_header())
                    {
                        Ok(header) => {
                            if header.block_hash() == ExecutionBlockHash::zero() {
                                reconstruct_default_header_block(
                                    blinded_block,
                                    header,
                                    &self.beacon_chain.spec,
                                )
                            } else {
                                // Add the block to the set requiring a by-range request.
                                let block_parts = BlockParts::new(blinded_block, header);
                                by_range_blocks.push(block_parts);
                                continue;
                            }
                        }
                        Err(e) => Err(BeaconChainError::BeaconStateError(e)),
                    }
                }
            };

            no_request
                .push_block_result(root, block_result, &self.beacon_chain.log)
                .await;
            requests.insert(root, no_request.clone());
        }

        // Now deal with the by_range requests. Sort them in order of increasing slot
        let mut by_range = EngineRequest::<T::EthSpec>::new_by_range();
        by_range_blocks.sort_by_key(|block_parts| block_parts.slot());
        for block_parts in by_range_blocks {
            let root = block_parts.root();
            by_range
                .push_block_parts(block_parts, &self.beacon_chain.log)
                .await;
            requests.insert(root, by_range.clone());
        }

        let mut result = vec![];
        for root in ordered_block_roots {
            if let Some(request) = requests.get(&root) {
                result.push((root, request.clone()))
            } else {
                crit!(
                    self.beacon_chain.log,
                    "Please notify the devs";
                    "beacon_block_streamer" => "request not found",
                    "root" => ?root,
                );
                no_request
                    .push_block_result(
                        root,
                        Err(Error::RequestNotFound.into()),
                        &self.beacon_chain.log,
                    )
                    .await;
                result.push((root, no_request.clone()));
            }
        }

        result
    }

    // used when the execution engine doesn't support the payload bodies methods
    async fn stream_blocks_fallback(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        debug!(
            self.beacon_chain.log,
            "Using slower fallback method of eth_getBlockByHash()"
        );
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
        let mut n_success = 0usize;
        let mut n_sent = 0usize;
        let mut engine_requests = 0usize;

        let payloads = match self.load_payloads(block_roots).await {
            Ok(payloads) => payloads,
            Err(e) => {
                error!(
                    self.beacon_chain.log,
                    "BeaconBlockStreamer: Failed to load payloads";
                    "error" => ?e
                );
                return;
            }
        };
        let requests = self.get_requests(payloads).await;

        for (root, request) in requests {
            if request.is_unsent().await {
                engine_requests += 1;
            }

            let result = request
                .get_block_result(&root, &self.execution_layer, &self.beacon_chain.log)
                .await;

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
            self.beacon_chain.log,
            "BeaconBlockStreamer finished";
            "requested blocks" => n_roots,
            "sent" => n_sent,
            "succeeded" => n_success,
            "failed" => (n_sent - n_success),
            "engine requests" => engine_requests,
        );
    }

    pub async fn stream(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        match self
            .execution_layer
            .get_engine_capabilities(None)
            .await
            .map_err(Box::new)
            .map_err(BeaconChainError::EngineGetCapabilititesFailed)
        {
            Ok(engine_capabilities) => {
                if engine_capabilities.get_payload_bodies_by_range_v1 {
                    self.stream_blocks(block_roots, sender).await;
                } else {
                    // use the fallback method
                    self.stream_blocks_fallback(block_roots, sender).await;
                }
            }
            Err(e) => {
                send_errors(block_roots, sender, e).await;
            }
        }
    }

    pub fn launch_stream(
        self: Arc<Self>,
        block_roots: Vec<Hash256>,
    ) -> impl Stream<Item = (Hash256, Arc<BlockResult<T::EthSpec>>)> {
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        debug!(
            self.beacon_chain.log,
            "Launching a BeaconBlockStreamer";
            "blocks" => block_roots.len(),
        );
        let executor = self.beacon_chain.task_executor.clone();
        executor.spawn(self.stream(block_roots, block_tx), "get_blocks_sender");
        UnboundedReceiverStream::new(block_rx)
    }
}

async fn send_errors<E: EthSpec>(
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
    use crate::test_utils::{test_spec, BeaconChainHarness, EphemeralHarnessType};
    use execution_layer::test_utils::Block;
    use std::sync::Arc;
    use std::sync::LazyLock;
    use tokio::sync::mpsc;
    use types::{
        ChainSpec, Epoch, EthSpec, FixedBytesExtended, Hash256, Keypair, MinimalEthSpec, Slot,
    };

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
            .logger(logging::test_logger())
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        harness.advance_slot();

        harness
    }

    #[tokio::test]
    async fn check_all_blocks_from_altair_to_electra() {
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch() as usize;
        let num_epochs = 10;
        let bellatrix_fork_epoch = 2usize;
        let capella_fork_epoch = 4usize;
        let deneb_fork_epoch = 6usize;
        let electra_fork_epoch = 8usize;
        let num_blocks_produced = num_epochs * slots_per_epoch;

        let mut spec = test_spec::<MinimalEthSpec>();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(bellatrix_fork_epoch as u64));
        spec.capella_fork_epoch = Some(Epoch::new(capella_fork_epoch as u64));
        spec.deneb_fork_epoch = Some(Epoch::new(deneb_fork_epoch as u64));
        spec.electra_fork_epoch = Some(Epoch::new(electra_fork_epoch as u64));
        let spec = Arc::new(spec);

        let harness = get_harness(VALIDATOR_COUNT, spec.clone());
        // go to bellatrix fork
        harness
            .extend_slots(bellatrix_fork_epoch * slots_per_epoch)
            .await;
        // extend half an epoch
        harness.extend_slots(slots_per_epoch / 2).await;
        // trigger merge
        harness
            .execution_block_generator()
            .move_to_terminal_block()
            .expect("should move to terminal block");
        let timestamp = harness.get_timestamp_at_slot() + harness.spec.seconds_per_slot;
        harness
            .execution_block_generator()
            .modify_last_block(|block| {
                if let Block::PoW(terminal_block) = block {
                    terminal_block.timestamp = timestamp;
                }
            });
        // finish out merge epoch
        harness.extend_slots(slots_per_epoch / 2).await;
        // finish rest of epochs
        harness
            .extend_slots((num_epochs - 1 - bellatrix_fork_epoch) * slots_per_epoch)
            .await;

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

use crate::early_attester_cache::EarlyAttesterCache;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BeaconStore};
use execution_layer::{ExecutionLayer, ExecutionPayloadBodyV1};
use slog::{crit, debug, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use store::DatabaseBlock;
use task_executor::TaskExecutor;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};
use types::{
    ChainSpec, EthSpec, ExecPayload, ExecutionBlockHash, ExecutionPayloadHeader, Hash256,
    SignedBeaconBlock, SignedBlindedBeaconBlock, Slot,
};

#[derive(Debug)]
pub enum Error {
    PayloadReconstructionError(Box<String>),
    BlocksByRangeFailure(Box<execution_layer::Error>),
    BlocksByHashFailure(Box<execution_layer::Error>),
    BlockNotFound,
}

// This is the same as a DatabaseBlock
// but the Arc allows us to avoid an
// unnecessary clone
enum LoadedBeaconBlock<E: EthSpec> {
    Full(Arc<SignedBeaconBlock<E>>),
    Blinded(SignedBlindedBeaconBlock<E>),
}
type LoadResult<E> = Result<Option<LoadedBeaconBlock<E>>, BeaconChainError>;
type BlockResult<E> = Result<Option<Arc<SignedBeaconBlock<E>>>, BeaconChainError>;

enum RequestState<E: EthSpec> {
    UnSent(Vec<(SignedBlindedBeaconBlock<E>, ExecutionPayloadHeader<E>)>),
    Sent(HashMap<Hash256, Arc<BlockResult<E>>>),
}

struct BodiesByHash<E: EthSpec> {
    hashes: Option<Vec<ExecutionBlockHash>>,
    state: RequestState<E>,
}
struct BodiesByRange<E: EthSpec> {
    start: u64,
    count: u64,
    state: RequestState<E>,
}

fn reconstruct_bocks<E: EthSpec>(
    block_map: &mut HashMap<Hash256, Arc<BlockResult<E>>>,
    parts: Vec<(
        SignedBlindedBeaconBlock<E>,
        ExecutionPayloadHeader<E>,
        Option<ExecutionPayloadBodyV1<E>>,
    )>,
) {
    for (blinded, header, maybe_payload_body) in parts {
        let root = blinded.canonical_root();

        if block_map.contains_key(&root) {
            // it's possible the same block is requested twice
            continue;
        }

        if let Some(payload_body) = maybe_payload_body {
            match payload_body.to_payload(header.clone()) {
                Ok(payload) => {
                    let header_from_payload = ExecutionPayloadHeader::from(payload.to_ref());
                    if header_from_payload == header {
                        block_map.insert(
                            root,
                            Arc::new(
                                blinded
                                    .try_into_full_block(Some(payload))
                                    .ok_or(BeaconChainError::AddPayloadLogicError)
                                    .map(Arc::new)
                                    .map(Some),
                            ),
                        );
                    } else {
                        block_map.insert(
                            root,
                            Arc::new(Err(BeaconChainError::InconsistentPayloadReconstructed {
                                slot: blinded.slot(),
                                exec_block_hash: header.block_hash(),
                                canonical_transactions_root: header.transactions_root(),
                                reconstructed_transactions_root: header_from_payload
                                    .transactions_root(),
                            })),
                        );
                    }
                }
                Err(string) => {
                    block_map.insert(
                        root,
                        Arc::new(Err(
                            Error::PayloadReconstructionError(Box::new(string)).into()
                        )),
                    );
                }
            }
        } else {
            block_map.insert(
                root,
                Arc::new(Err(BeaconChainError::BlockHashMissingFromExecutionLayer(
                    header.block_hash(),
                ))),
            );
        }
    }
}

impl<E: EthSpec> BodiesByHash<E> {
    pub fn new(
        maybe_block_header: Option<(SignedBlindedBeaconBlock<E>, ExecutionPayloadHeader<E>)>,
    ) -> Self {
        if let Some((blinded_block, header)) = maybe_block_header {
            Self {
                hashes: Some(vec![header.block_hash()]),
                state: RequestState::UnSent(vec![(blinded_block, header)]),
            }
        } else {
            Self {
                hashes: None,
                state: RequestState::UnSent(vec![]),
            }
        }
    }

    pub fn push_block(
        &mut self,
        blinded_block: SignedBlindedBeaconBlock<E>,
        header: ExecutionPayloadHeader<E>,
    ) -> Result<(), (SignedBlindedBeaconBlock<E>, ExecutionPayloadHeader<E>)> {
        if self
            .hashes
            .as_ref()
            .map_or(false, |hashes| hashes.len() == 32)
        {
            // this request is full
            return Err((blinded_block, header));
        }
        match &mut self.state {
            RequestState::Sent(_) => Err((blinded_block, header)),
            RequestState::UnSent(blocks_and_headers) => {
                self.hashes.get_or_insert(vec![]).push(header.block_hash());
                blocks_and_headers.push((blinded_block, header));

                Ok(())
            }
        }
    }

    async fn execute(&mut self, execution_layer: &ExecutionLayer<E>) {
        if let RequestState::UnSent(blocks_and_headers_ref) = &mut self.state {
            if let Some(hashes) = self.hashes.take() {
                let blocks_and_headers = std::mem::take(blocks_and_headers_ref);
                let mut block_map = HashMap::new();
                match execution_layer
                    .get_payload_bodies_by_hash(hashes.clone())
                    .await
                {
                    Ok(bodies) => {
                        let mut body_map = hashes
                            .into_iter()
                            .zip(bodies.into_iter().chain(std::iter::repeat(None)))
                            .collect::<HashMap<_, _>>();

                        let mut parts = vec![];
                        for (blinded_block, header) in blocks_and_headers {
                            if block_map.contains_key(&blinded_block.canonical_root()) {
                                // it's possible the same block is requested twice
                                continue;
                            }

                            let block_hash = header.block_hash();
                            parts.push((
                                blinded_block,
                                header,
                                body_map.remove(&block_hash).flatten(),
                            ));
                        }

                        reconstruct_bocks(&mut block_map, parts);
                    }
                    Err(e) => {
                        let block_result =
                            Arc::new(Err(Error::BlocksByHashFailure(Box::new(e)).into()));
                        for (blinded_block, _) in blocks_and_headers {
                            block_map.insert(blinded_block.canonical_root(), block_result.clone());
                        }
                    }
                }
                self.state = RequestState::Sent(block_map);
            }
        }
    }

    pub async fn get_block_result(
        &mut self,
        root: &Hash256,
        execution_layer: &ExecutionLayer<E>,
    ) -> Option<Arc<BlockResult<E>>> {
        self.execute(execution_layer).await;
        if let RequestState::Sent(map) = &self.state {
            return map.get(root).map(|result| result.clone());
        }
        // Shouldn't reach this point
        None
    }
}

impl<E: EthSpec> BodiesByRange<E> {
    pub fn new(
        maybe_block_header: Option<(SignedBlindedBeaconBlock<E>, ExecutionPayloadHeader<E>)>,
    ) -> Self {
        if let Some((blinded_block, header)) = maybe_block_header {
            Self {
                start: header.block_number(),
                count: 1,
                state: RequestState::UnSent(vec![(blinded_block, header)]),
            }
        } else {
            Self {
                start: 0,
                count: 0,
                state: RequestState::UnSent(vec![]),
            }
        }
    }

    pub fn push_block(
        &mut self,
        blinded_block: SignedBlindedBeaconBlock<E>,
        header: ExecutionPayloadHeader<E>,
    ) -> Result<(), (SignedBlindedBeaconBlock<E>, ExecutionPayloadHeader<E>)> {
        if self.count == 32 {
            return Err((blinded_block, header));
        }

        match &mut self.state {
            RequestState::Sent(_) => return Err((blinded_block, header)),
            RequestState::UnSent(blocks_and_headers) => {
                let block_number = header.block_number();
                if self.count == 0 {
                    self.start = block_number;
                    self.count = 1;
                    blocks_and_headers.push((blinded_block, header));
                    Ok(())
                } else {
                    // need to figure out if this block fits in the request
                    if block_number < self.start || self.start + 31 < block_number {
                        return Err((blinded_block, header));
                    }

                    blocks_and_headers.push((blinded_block, header));
                    if self.start + self.count <= block_number {
                        self.count = block_number - self.start + 1;
                    }

                    Ok(())
                }
            }
        }
    }

    async fn execute(&mut self, execution_layer: &ExecutionLayer<E>) {
        if let RequestState::UnSent(blocks_and_headers_ref) = &mut self.state {
            let blocks_and_headers = std::mem::take(blocks_and_headers_ref);

            let mut block_map = HashMap::new();
            match execution_layer
                .get_payload_bodies_by_range(self.start, self.count)
                .await
            {
                Ok(bodies) => {
                    let mut range_map = (self.start..(self.start + self.count))
                        .into_iter()
                        .zip(bodies.into_iter().chain(std::iter::repeat(None)))
                        .collect::<HashMap<_, _>>();

                    let mut parts = vec![];
                    for (blinded_block, header) in blocks_and_headers {
                        if block_map.contains_key(&blinded_block.canonical_root()) {
                            // it's possible the same block is requested twice
                            continue;
                        }

                        let block_number = header.block_number();
                        parts.push((
                            blinded_block,
                            header,
                            range_map.remove(&block_number).flatten(),
                        ));
                    }
                    reconstruct_bocks(&mut block_map, parts);
                }
                Err(e) => {
                    let block_result =
                        Arc::new(Err(Error::BlocksByRangeFailure(Box::new(e)).into()));
                    for (blinded_block, _) in blocks_and_headers {
                        block_map.insert(blinded_block.canonical_root(), block_result.clone());
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
    ) -> Option<Arc<BlockResult<E>>> {
        self.execute(execution_layer).await;
        if let RequestState::Sent(map) = &self.state {
            return map.get(root).map(|result| result.clone());
        }
        // Shouldn't reach this point
        None
    }
}

#[derive(Clone)]
enum EngineRequest<E: EthSpec> {
    ByHash(Arc<RwLock<BodiesByHash<E>>>),
    ByRange(Arc<RwLock<BodiesByRange<E>>>),
    // When we already have the data or there's an error
    NoRequest(Arc<RwLock<HashMap<Hash256, Arc<BlockResult<E>>>>>),
}

impl<E: EthSpec> EngineRequest<E> {
    pub fn new_by_hash() -> Self {
        Self::ByHash(Arc::new(RwLock::new(BodiesByHash::new(None))))
    }
    pub fn new_by_range() -> Self {
        Self::ByRange(Arc::new(RwLock::new(BodiesByRange::new(None))))
    }
    pub fn new_no_request() -> Self {
        Self::NoRequest(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn push_blinded_block(
        &mut self,
        blinded_block: SignedBlindedBeaconBlock<E>,
        header: ExecutionPayloadHeader<E>,
        log: &Logger,
    ) {
        match self {
            Self::ByHash(bodies_by_hash) => {
                let mut write_guard = bodies_by_hash.write().await;

                if let Err((blinded_block, header)) = write_guard.push_block(blinded_block, header)
                {
                    drop(write_guard);
                    let new_by_hash = BodiesByHash::new(Some((blinded_block, header)));
                    *self = Self::ByHash(Arc::new(RwLock::new(new_by_hash)));
                }
            }
            Self::ByRange(bodies_by_range) => {
                let mut write_guard = bodies_by_range.write().await;

                if let Err((blinded_block, header)) = write_guard.push_block(blinded_block, header)
                {
                    drop(write_guard);
                    let new_by_range = BodiesByRange::new(Some((blinded_block, header)));
                    *self = Self::ByRange(Arc::new(RwLock::new(new_by_range)));
                }
            }
            Self::NoRequest(_) => {
                // this should _never_ happen
                crit!(
                    log,
                    "Please notify the devs: beacon_block_streamer: push_blinded_block called on NoRequest variant"
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
                    "Please notify the devs: beacon_block_streamer: push_block_result called on ByRange"
                );
            }
            Self::ByHash(_) => {
                // this should _never_ happen
                crit!(
                    log,
                    "Please notify the devs: beacon_block_streamer: push_block_result called on ByHash"
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
                    .get_block_result(root, execution_layer)
                    .await
            }
            Self::ByHash(by_hash) => {
                by_hash
                    .write()
                    .await
                    .get_block_result(root, execution_layer)
                    .await
            }
            Self::NoRequest(map) => map.read().await.get(root).map(|block| block.clone()),
        }.unwrap_or_else(|| {
            crit!(
                log,
                "Please notify the devs: beacon_block_streamer: block_result not found for block {:?}",
                root
            );
            Arc::new(Err(Error::BlockNotFound.into()))
        })
    }
}

pub struct BeaconBlockStreamer<T: BeaconChainTypes> {
    execution_layer: ExecutionLayer<T::EthSpec>,
    finalized_slot: Slot,
    early_attester_cache: Option<EarlyAttesterCache<T::EthSpec>>,
    store: BeaconStore<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconBlockStreamer<T> {
    pub fn new(
        execution_layer: ExecutionLayer<T::EthSpec>,
        finalized_slot: Slot,
        store: BeaconStore<T>,
        early_attester_cache: Option<EarlyAttesterCache<T::EthSpec>>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self {
            execution_layer,
            finalized_slot,
            store,
            early_attester_cache,
            spec,
            log,
        }
    }

    fn load_payloads(&self, block_roots: Vec<Hash256>) -> Vec<(Hash256, LoadResult<T::EthSpec>)> {
        let mut db_blocks = Vec::new();

        for root in block_roots {
            if let Some(block) = self
                .early_attester_cache
                .as_ref()
                .and_then(|cache| cache.get_block(root))
            {
                db_blocks.push((root, Ok(Some(LoadedBeaconBlock::Full(block)))));
                continue;
            }

            match self.store.try_get_full_block(&root) {
                Err(e) => db_blocks.push((root, Err(e.into()))),
                Ok(opt_block) => db_blocks.push((
                    root,
                    Ok(opt_block.map(|db_block| match db_block {
                        DatabaseBlock::Full(block) => LoadedBeaconBlock::Full(Arc::new(block)),
                        DatabaseBlock::Blinded(block) => LoadedBeaconBlock::Blinded(block),
                    })),
                )),
            }
        }

        db_blocks
    }

    // Pre-process the loaded blocks into execution engine requests, preserving the order of the blocks.
    async fn get_requests(
        &self,
        loaded: Vec<(Hash256, LoadResult<T::EthSpec>)>,
    ) -> (Vec<Hash256>, HashMap<Hash256, EngineRequest<T::EthSpec>>) {
        let mut ordered_block_roots = Vec::new();
        let mut requests = HashMap::new();

        // separate off the by_range blocks so they can be sorted and then processed
        let mut by_range_blocks: Vec<(
            Hash256,
            SignedBlindedBeaconBlock<T::EthSpec>,
            ExecutionPayloadHeader<T::EthSpec>,
        )> = vec![];
        let mut by_hash = EngineRequest::new_by_hash();
        let mut no_request = EngineRequest::new_no_request();

        for (root, load_result) in loaded {
            // preserve the order of the requested blocks
            ordered_block_roots.push(root);

            match load_result {
                Ok(Some(LoadedBeaconBlock::Blinded(blinded_block))) => {
                    match blinded_block
                        .message()
                        .execution_payload()
                        .map(|payload| payload.to_execution_payload_header())
                    {
                        Ok(header) => {
                            if blinded_block.message().slot() <= self.finalized_slot {
                                // this is a by_range request
                                by_range_blocks.push((root, blinded_block, header));
                            } else {
                                // this is a by_hash request
                                by_hash
                                    .push_blinded_block(blinded_block, header, &self.log)
                                    .await;
                                requests.insert(root, by_hash.clone());
                            }
                        }
                        Err(_) => {
                            no_request
                                .push_block_result(
                                    root,
                                    Err(BeaconChainError::BlockVariantLacksExecutionPayload(root)),
                                    &self.log,
                                )
                                .await;
                            requests.insert(root, no_request.clone());
                        }
                    }
                }
                // no request when there's an error, or the block doesn't exist, or we already have the full block
                no_request_load_result => {
                    let block_result = match no_request_load_result {
                        Err(e) => Err(e),
                        Ok(None) => Ok(None),
                        Ok(Some(LoadedBeaconBlock::Full(full_block))) => Ok(Some(full_block)),
                        // unreachable due to the match statement above
                        Ok(Some(LoadedBeaconBlock::Blinded(_))) => unreachable!(),
                    };
                    no_request
                        .push_block_result(root, block_result, &self.log)
                        .await;
                    requests.insert(root, no_request.clone());
                }
            }
        }

        // Now deal with the by_range requests. Sort them in order of increasing slot
        let mut by_range = EngineRequest::<T::EthSpec>::new_by_range();
        by_range_blocks.sort_by(|(_, blinded_block_a, _), (_, blinded_block_b, _)| {
            // this unwrap shouldn't occur as slot is never u64::NAN
            blinded_block_a
                .message()
                .slot()
                .partial_cmp(&blinded_block_b.message().slot())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for (root, blinded_block, header) in by_range_blocks {
            by_range
                .push_blinded_block(blinded_block, header, &self.log)
                .await;
            requests.insert(root, by_range.clone());
        }

        (ordered_block_roots, requests)
    }

    async fn stream_blocks(
        &self,
        block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<BlockResult<T::EthSpec>>)>,
    ) {
        let payloads = self.load_payloads(block_roots);
        let (roots, request_map) = self.get_requests(payloads).await;

        for root in roots {
            let result = if let Some(request) = request_map.get(&root) {
                request
                    .get_block_result(&root, &self.execution_layer, &self.log)
                    .await
            } else {
                crit!(
                    self.log,
                    "Please notify the devs: beacon_block_streamer: request not found for block {:?}",
                    root
                );
                Arc::new(Err(Error::BlockNotFound.into()))
            };

            if let Err(_) = sender.send((root, result)) {
                break;
            }
        }
    }

    pub fn stream(
        self,
        block_roots: Vec<Hash256>,
        executor: &TaskExecutor,
        chain: &Arc<BeaconChain<T>>,
    ) -> impl Stream<Item = (Hash256, Arc<BlockResult<T::EthSpec>>)> {
        let (block_tx, block_rx) = mpsc::unbounded_channel();
        let chain = chain.clone();

        executor.spawn(
            async move {
                match self
                    .execution_layer
                    .get_engine_capabilities(None)
                    .await
                    .map_err(Box::new)
                    .map_err(BeaconChainError::EngineGetCapabilititesFailed)
                {
                    Ok(capabilities) => {
                        // use the fallback method
                        if capabilities.get_payload_bodies_by_hash_v1
                            && capabilities.get_payload_bodies_by_range_v1
                        {
                            self.stream_blocks(block_roots, block_tx).await;
                        } else {
                            for root in block_roots {
                                let block_result = if let Some(block) = self
                                    .early_attester_cache
                                    .as_ref()
                                    .and_then(|cache| cache.get_block(root))
                                {
                                    Ok(Some(block))
                                } else {
                                    chain
                                        .get_block(&root)
                                        .await
                                        .map(|opt_block| opt_block.map(Arc::new))
                                };
                                if let Err(_) = block_tx.send((root, Arc::new(block_result))) {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let result = Arc::new(Err(e));
                        for root in block_roots {
                            if let Err(_) = block_tx.send((root, result.clone())) {
                                break;
                            }
                        }
                    }
                }
            },
            "get_blocks_sender",
        );

        UnboundedReceiverStream::new(block_rx)
    }
}

impl From<Error> for BeaconChainError {
    fn from(value: Error) -> Self {
        BeaconChainError::BlockStreamerError(value)
    }
}

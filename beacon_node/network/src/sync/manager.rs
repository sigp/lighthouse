
const MAXIMUM_BLOCKS_PER_REQUEST: usize = 10;
const SIMULTANEOUS_REQUESTS: usize = 10;
use super::simple_sync::FUTURE_SLOT_TOLERANCE;

struct Chunk {
    id: usize,
    start_slot: Slot,
    end_slot: Slot,
    }


struct CompletedChunk {
    peer_id: PeerId,
    chunk: Chunk,
    blocks: Vec<BeaconBlock>,
}

struct ProcessedChunk {
    peer_id: PeerId,
    chunk: Chunk,
}

#[derive(PartialEq)]
pub enum SyncState {
    Idle,
    Downloading,
    ColdSync {
        max_wanted_slot: Slot,
        max_wanted_hash: Hash256,
    }
}

pub enum SyncManagerState {
    RequestBlocks(peer_id, BeaconBlockRequest),
    Stalled,
    Idle, 
}

pub struct PeerSyncInfo {
    peer_id: PeerId,
    fork_version: [u8,4],
    finalized_root: Hash256,
    finalized_epoch: Epoch,
    head_root: Hash256,
    head_slot: Slot,
    requested_slot_skip: Option<(Slot, usize)>,
}

pub(crate) struct SyncManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A mapping of Peers to their respective PeerSyncInfo.
    available_peers: HashMap<PeerId, PeerSyncInfo>,
    wanted_chunks: Vec<Chunk>,
    pending_chunks: HashMap<PeerId,Chunk>,
    completed_chunks: Vec<Chunk>,
    processed_chunks: Vec<Chunk>, // ordered
    multi_peer_sections: HashMap<PeerId, MultiPeerSection>

    current_requests: usize,
    latest_wanted_slot: Option<Slot, Hash256>,
    sync_status: SyncStatus,
    to_process_chunk_id: usize,
    log: Logger,

}

impl<T: BeaconChainTypes> SyncManager<T> {
    /// Adds a sync-able peer and determines which blocks to download given the current state of
    /// the chain, known peers and currently requested blocks.
    fn add_sync_peer(&mut self, peer_id: PeerId, remote: PeerSyncInfo, network &mut NetworkContext) {

        let local = PeerSyncInfo::from(&self.chain);
        let remote_finalized_slot = remote.finalized_epoch.start_slot(T::EthSpec::slots_per_epoch());
        let local_finalized_slot = local.finalized_epoch.start_slot(T::EthSpec::slots_per_epoch());

        // cold sync
        if remote_finalized_slot > local.head_slot {
            if let SyncState::Idle || SyncState::Downloading  = self.sync_state {
                info!(self.log, "Cold Sync Started", "start_slot" => local.head_slot, "latest_known_finalized" => remote_finalized_slot); 
                self.sync_state = SyncState::ColdSync{Slot::from(0), remote.finalized_hash}
            }

            if let SyncState::ColdSync{max_wanted_slot, max_wanted_hjash } = self.sync_state {

            // We don't assume that our current head is the canonical chain. So we request blocks from
            // our last finalized slot to ensure we are on the finalized chain.
            if max_wanted_slot < remote_finalized_slot {
                let remaining_blocks = remote_finalized_slot - max_wanted_slot;
                for chunk in (0..remaining_blocks/MAXIMUM_BLOCKS_PER_REQUEST) { 
                    self.wanted_chunks.push(
                        Chunk {
                            id: self.current_chunk_id,
                            previous_chunk: self.curent_chunk_id.saturating_sub(1),
                            start_slot: chunk*MAXIMUM_BLOCKS_PER_REQUEST + self.last_wanted_slot,
                            end_slot: (section+1)*MAXIMUM_BLOCKS_PER_REQUEST +self.last_wanted_slot,
                        })
                    self.current_chunk_id +=1;
                }
                
                // add any extra partial chunks
                self.pending_section.push( Section {
                    start_slot: (remaining_blocks/MAXIMUM_BLOCKS_PER_REQUEST) + 1,
                    end_slot: remote_finalized_slot,
                })
                self.current_chunk_id +=1;

                info!(self.log, "Cold Sync Updated", "start_slot" => local.head_slot, "latest_known_finalized" => remote_finalized_slot); 

                self.sync_state = SyncState::ColdSync{remote_finalized_slot, remote.finalized_hash}
            }
        }

        else { // hot sync 
        if remote_head_slot > self.chain.head().beacon_state.slot {
            if let SyncState::Idle = self.sync_state {
                self.sync_state = SyncState::Downloading
                info!(self.log, "Sync Started", "start_slot" => local.head_slot, "latest_known_head" => remote.head_slot.as_u64()); 
            }
            self.latest_known_slot = remote_head_slot; 
            //TODO Build requests.
            }
        }

        available_peers.push(remote);

    }

    pub fn add_blocks(&mut self, chunk_id: RequestId, peer_id: PeerId, blocks: Vec<BeaconBlock>) {

        if SyncState::ColdSync{max_wanted_slot, max_wanted_hash} = self.sync_state {

            let chunk = match self.pending_chunks.remove(&peer_id) {
                Some(chunks) => {
                    match chunks.find(|chunk| chunk.id == chunk_id) {
                        Some(chunk) => chunk,
                        None => {
                    warn!(self.log, "Received blocks for an unknown chunk";
                          "peer"=> peer_id);
                    return;
                        }
                    }
                },
                None =>  {
                    warn!(self.log, "Received blocks without a request";
                          "peer"=> peer_id);
                return;
                }
            };

            // add to completed
            self.current_requests -= 1;
            self.completed_chunks.push(CompletedChunk(peer_id, Chunk));
        }
    }

    pub fn inject_error(id: RequestId, peer_id) {
        if let SyncState::ColdSync{ _max_wanted_slot, _max_wanted_hash } {
            match self.pending_chunks.get(&peer_id) {
                Some(chunks) => {
                    if let Some(pos) = chunks.iter().position(|c| c.id == id) {
                        chunks.remove(pos);
                    }
                },
                None =>  {
                    debug!(self.log,
                           "Received an error for an unknown request";
                           "request_id" => id,
                           "peer" => peer_id
                           );
                }
            }
        }
    }

    pub fn poll(&mut self) -> SyncManagerState {

        // if cold sync
        if let SyncState::ColdSync(waiting_slot, max_wanted_slot, max_wanted_hash) = self.sync_state {

            // Try to process completed chunks
            for completed_chunk in self.completed_chunks {
                let chunk = completed_chunk.1;
                let last_chunk_id = {
                    let no_processed_chunks = self.processed_chunks.len();
                    if elements == 0 { 0 } else { self.processed_chunks[no_processed_chunks].id }
                };
                if chunk.id == last_chunk_id + 1 {
                // try and process the chunk
                for block in chunk.blocks {
                    let processing_result = self.chain.process_block(block.clone());

                    if let Ok(outcome) = processing_result {
                        match outcome {
                            BlockProcessingOutCome::Processed { block_root} => {
                                // block successfully processed
                            },
                            BlockProcessingOutcome::BlockIsAlreadyKnown => { 
                                warn!(
                                    self.log, "Block Already Known";
                                    "source" => source,
                                    "sync" => "Cold Sync",
                                    "parent_root" => format!("{}", parent),
                                    "baby_block_slot" => block.slot,
                                    "peer" => format!("{:?}", chunk.0),
                                );
                            },
                            _ => {
                                // An error has occurred
                                // This could be due to the previous chunk or the current chunk.
                                // Re-issue both.
                                warn!(
                                    self.log, "Faulty Chunk";
                                    "source" => source,
                                    "sync" => "Cold Sync",
                                    "parent_root" => format!("{}", parent),
                                    "baby_block_slot" => block.slot,
                                    "peer" => format!("{:?}", chunk.0),
                                    "outcome" => format!("{:?}", outcome),
                                );

                                // re-issue both chunks
                                // if both are the same peer. Downgrade the peer.
                                let past_chunk = self.processed_chunks.pop()
                                self.wanted_chunks.insert(0, chunk.clone());
                                self.wanted_chunks.insert(0, past_chunk.clone());
                                if chunk.0 == past_chunk.peer_id {
                                    // downgrade peer
                                    return SyncManagerState::DowngradePeer(chunk.0);
                                }
                                break;
                            }
                        }
                    }
                }
                // chunk successfully processed
                debug!(self.log,
                       "Chunk Processed";
                       "id" => chunk.id
                       "start_slot" => chunk.start_slot,
                       "end_slot" => chunk.end_slot,
                       );
                self.processed_chunks.push(chunk);
                }
            }

            // chunks completed, update the state
            self.sync_state = SyncState::ColdSync{waiting_slot, max_wanted_slot, max_wanted_hash};

            // Remove stales

            // Spawn requests
            if self.current_requests <= SIMULTANEOUS_REQUESTS {
                if !self.wanted_chunks.is_empty() {
                    let chunk = self.wanted_chunks.remove(0);
                    for n in (0..self.peers.len()).rev() {
                        let peer = self.peers.swap_remove(n);
                        let peer_finalized_slot = peer.finalized_epoch.start_slot(T::EthSpec::slots_per_epoch());
                        if peer_finalized_slot >= chunk.end_slot {
                                *self.pending.chunks.entry(&peer_id).or_insert_with(|| Vec::new).push(chunk);
                                self.active_peers.push(peer);
                                self.current_requests +=1;
                                let block_request = BeaconBlockRequest { 
                                    head_block_root,
                                    start_slot: chunk.start_slot,
                                    count: chunk.end_slot - chunk.start_slot
                                    step: 1
                                }
                                return SyncManagerState::BlockRequest(peer, block_request);
                            }
                    }
                    // no peers for this chunk
                    self.wanted_chunks.push(chunk);
                    return SyncManagerState::Stalled
                }
            }
        }

        // if hot sync
        return SyncManagerState::Idle

    }

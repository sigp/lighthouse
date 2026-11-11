use crate::NetworkBeaconProcessor;
use crate::service::NetworkMessage;
use crate::sync::SyncMessage;
use beacon_chain::BeaconChainTypes;
use bytes::Bytes;
use lighthouse_network::libp2p::swarm::ConnectionId;
use lighthouse_network::{PeerAction, PeerId, ReportSource};
use rand::seq::SliceRandom;
use slot_clock::SlotClock;
use ssz::{Decode, DecodeError, Encode};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::coop::consume_budget;
use tokio::time::{Instant, sleep_until};
use tracing::{debug, error, warn};
use types::{ChunkBitmap, ChunkMetadata, EthSpec, Hash256, PayloadChunk, SignedBeaconBlock, Slot};
use waggle::handler::{ObjectPieces, PieceSender, TopicEvent};

/// The number of peers each valid chunk is pushed to, if as many peers track the payload and aren't
/// known to have the chunk. The other peers learn about the chunk from our metadata, and may request
/// it.
///
/// Peers tell us that they track a payload by sending metadata about it. We never push chunks to
/// peers that didn't, as they would have to drop them: chunks of untracked payloads are not
/// buffered.
const PUSH_PEERS: usize = 2;

/// How long after the first chunk of a payload arrived we push its chunks on. Later ones are
/// only announced, and peers request them. A payload we publish is pushed whenever.
///
/// Pushes are what gets a payload to its first chunks everywhere, and what peers that withhold
/// chunks can't stop. Later, most of what is pushed arrives where it was requested already.
const PUSH_PHASE: Duration = Duration::from_millis(250);

/// How many times its share of our pushes of a payload a peer may get at most, where its share is
/// what it would get if the pushes were spread evenly over our peers, see `max_pushes_per_peer`.
///
/// Without a limit, the first `PUSH_PEERS` peers to track a payload we have every chunk of, as
/// when we publish it, would get all of its chunks from us, and the others none. The higher the
/// limit, the more of the pushes go to the peers that track the payload first, and the fewer are
/// lost if some of our peers never track it.
const MAX_PUSH_SHARE: usize = 2;

/// How long to wait after registering a payload, i.e. receiving its block, before requesting the
/// chunks we lack. Chunks are still being pushed to us in the meantime, and requesting them would
/// waste the bandwidth of our peers.
///
/// With a low `PUSH_PEERS`, a node gets the last chunks of a small payload by requesting them, so
/// this is most of what a small payload takes to arrive. In simulations, 100 ms made small
/// payloads arrive as fast as `PUSH_PEERS` 10 did, and cost payloads of 1 MB and more little, as
/// the peers that have their chunks early are the ones with bandwidth to spare.
const REQUEST_DELAY: Duration = Duration::from_millis(100);

/// How long to wait for a requested chunk before requesting it again, possibly from another peer,
/// not counting the time it takes to send the chunk, see `REQUEST_TIMEOUT_PER_BYTE`.
///
/// A peer that announces chunks and never sends them holds up each chunk we request from it for
/// this long, so it should be no longer than an honest peer needs.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

/// The time added to `REQUEST_TIMEOUT` for every byte of the chunks of a payload, see
/// `request_timeout`: a peer needs longer to send a long chunk than a short one. This allows for
/// 0.5 Mbit/s, which makes 1.5 s for the chunks of a 4 MB payload.
const REQUEST_TIMEOUT_PER_BYTE: Duration = Duration::from_micros(16);

/// The time between the announcements of what we have of a payload, other than the first one
/// and the one of the complete payload, which are made right away.
const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(50);

/// How long to wait before trying again to request chunks from a peer whose send queue was full,
/// so that the request could not be queued.
const REQUEST_RETRY_DELAY: Duration = Duration::from_millis(100);

/// The number of slots after its own that a payload is tracked for, i.e. disseminated.
///
/// Nodes that don't get a payload during its slot can so still get it from us in the next one,
/// when they need it to import the next block. Sync would only look it up by then as well.
const TRACKED_SLOTS_AFTER_OWN: u64 = 1;

/// The number of slots after its tracking window that the senders of chunks of a payload are not
/// penalized for, see `PayloadDisseminationService::previous_payloads`.
const PREVIOUS_PAYLOAD_SLOTS: u64 = 1;

/// The maximum number of requests outstanding with a peer. Bounds the load on the publisher, which
/// every peer hears from first, and spreads the requests over the peers.
const MAX_REQUESTS_PER_PEER: usize = 1;

/// The number of requests a peer may have left unanswered, i.e. let time out, before we stop
/// requesting chunks from it. Every chunk we lacked that the peer sends us makes up for one.
/// Among the peers below the limit, the ones that left the fewest unanswered are asked first.
///
/// A peer that announces chunks and never sends them holds up each chunk we request from it for
/// the timeout, and it is the only one to ask for the chunks that it alone claims to have. The
/// peer is not penalized: an honest one with a slow uplink leaves requests unanswered too, and
/// makes up for them with the chunks it pushes.
const MAX_UNANSWERED_REQUESTS: usize = 1;

/// How long a payload may stay unknown after a peer first announced it, before we look up its
/// block.
const UNKNOWN_PAYLOAD_LOOKUP_DELAY: Duration = Duration::from_secs(1);

/// The maximum number of unknown payloads a peer may have announced at a time, which bounds what
/// peers can make us remember and look up.
///
/// Peers usually track one payload per slot of the tracking window, and so announce two, or three
/// around the end of a slot. They track more if they imported several blocks of a slot, as when
/// its proposer equivocated.
const MAX_UNKNOWN_PAYLOADS_PER_PEER: usize = 4;

/// The fork digest of a topic.
pub(crate) type ForkDigest = [u8; 4];

/// The peers on the topic.
type TopicPeers = HashMap<PeerId, Peer>;

/// A message to the payload dissemination service of a topic.
#[derive(Debug)]
pub(crate) enum PayloadDisseminationMessage<E: EthSpec> {
    /// A peer subscribed to the topic on the connection `connection_id`. Pieces queued on `sender`
    /// are sent to it.
    PeerSubscribed {
        peer_id: PeerId,
        connection_id: ConnectionId,
        sender: PieceSender,
    },
    NewPayload(NewPayload<E>),
}

/// A payload to track, whose chunks are disseminated on the topic of the fork digest at `slot`.
#[derive(Debug)]
pub struct NewPayload<E: EthSpec> {
    pub payload_chunks_root: Hash256,
    pub block_root: Hash256,
    pub slot: Slot,
    /// The chunks of the payload, if we have them already, as we do when publishing it.
    pub chunks: Option<Vec<Arc<PayloadChunk<E>>>>,
}

impl<E: EthSpec> NewPayload<E> {
    /// Returns the payload `block` commits to, if its bid commits to payload chunks.
    pub fn of_block(block_root: Hash256, block: &SignedBeaconBlock<E>) -> Option<Self> {
        let payload_chunks_root = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .ok()?
            .message()
            .payload_chunks_root()
            .ok()?;
        Some(Self {
            payload_chunks_root,
            block_root,
            slot: block.slot(),
            chunks: None,
        })
    }
}

/// Disseminates the payloads of one topic, i.e. of one fork digest, for as long as we are
/// subscribed to the topic.
pub struct PayloadDisseminationService<T: BeaconChainTypes> {
    /// The fork digest of the topic.
    fork_digest: ForkDigest,
    message_recv: mpsc::Receiver<PayloadDisseminationMessage<T::EthSpec>>,
    /// The events of the topic. Dropping the receiver unsubscribes from the topic.
    topic_events: async_channel::Receiver<TopicEvent>,
    /// Resolves once we are to unsubscribe from the topic.
    unsubscribe: oneshot::Receiver<()>,
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    /// When to next clean up: once the tracking window moved on, see `clean_up`.
    next_clean_up: Instant,
    /// Whether a peer may have made chunks requestable since we last requested any, see
    /// `request_missing_chunks`.
    requests_pending: bool,
    slot_clock: T::SlotClock,
    /// The peers on the topic.
    peers: TopicPeers,
    payloads: HashMap<Hash256, Payload<T::EthSpec>>,
    /// The payloads in their tracking window that peers announced and we don't track, by block
    /// root. We keep who announced them and what they have, see `UnknownPayload`.
    unknown_payloads: HashMap<Hash256, UnknownPayload<T::EthSpec>>,
    /// The payloads whose tracking window ended in the last `PREVIOUS_PAYLOAD_SLOTS` slots, by
    /// block root, with their slots.
    ///
    /// Peers may have sent us chunks of them while we still tracked them, which arrive after. We
    /// drop these like any chunk of an untracked payload, but don't penalize their senders.
    previous_payloads: Vec<(Hash256, Slot)>,
}

/// A payload peers announced that we don't track, as we don't know its block.
///
/// We remember who announced it, to look up the block from them if it doesn't reach us, and what
/// they have, to know that once we track the payload, see `Payload::adopt_unknown`.
struct UnknownPayload<E: EthSpec> {
    /// The peers that announced the payload, with the metadata each last sent. The slot is what
    /// the peer claims: we can't tell whether it is right before we know the block, so peers may
    /// disagree on it.
    peers: HashMap<PeerId, ChunkMetadata<E>>,
    /// When to look up the block of the payload, if it is still unknown by then:
    /// `UNKNOWN_PAYLOAD_LOOKUP_DELAY` after the first peer announced it. `None` once we did.
    lookup_at: Option<Instant>,
}

/// A peer on the topic, as of its newest connection.
///
/// The two subscriptions with a peer, ours to it and its to us, are reported on different channels,
/// so their events are not ordered relative to each other: those of a previous connection can
/// arrive after those of the current one. The connection tells them apart. A peer has one
/// connection at a time, and libp2p assigns connection IDs from a counter, so the higher ID is the
/// newer connection. Events of a newer connection replace what we know about the peer, and events
/// of an older one are ignored, see `peer_on_connection`.
struct Peer {
    /// The newest connection of the peer we heard of, which the fields below are about.
    connection_id: ConnectionId,
    /// Queues pieces for the peer, if it is subscribed to us.
    sender: Option<PieceSender>,
    /// Whether our subscription stream to the peer is open.
    subscribed: bool,
    /// The number of our requests that the peer left unanswered, less the chunks we lacked that
    /// it sent us since, see `MAX_UNANSWERED_REQUESTS`.
    unanswered_requests: usize,
}

impl Peer {
    fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            sender: None,
            subscribed: false,
            unanswered_requests: 0,
        }
    }

    /// Notes that the peer did not send a chunk we requested from it within `REQUEST_TIMEOUT`.
    fn request_timed_out(&mut self) {
        self.unanswered_requests = self.unanswered_requests.saturating_add(1);
    }

    /// Notes that the peer sent us a chunk we lacked, which makes up for an unanswered request.
    fn sent_new_chunk(&mut self) {
        self.unanswered_requests = self.unanswered_requests.saturating_sub(1);
    }

    /// Whether either subscription is alive. The other one may still be established, or again:
    /// the peer can subscribe to us again on the same connection.
    fn keep(&self) -> bool {
        self.subscribed
            || self
                .sender
                .as_ref()
                .is_some_and(|sender| !sender.is_closed())
    }

    fn sender(&self) -> Option<&PieceSender> {
        // Ignore peers with a closed sender or if the subscription isn't mutual.
        if self.subscribed
            && let Some(sender) = self.sender.as_ref()
            && !sender.is_closed()
        {
            Some(sender)
        } else {
            None
        }
    }
}

/// Returns what we know about `peer_id` on the connection `connection_id`, to apply an event of
/// that connection to. Returns `None` if the event is stale, as the peer has a newer connection.
///
/// If the connection is newer than the one we know, what we know is replaced, which drops the
/// sender of the previous connection.
fn peer_on_connection(
    peers: &mut TopicPeers,
    peer_id: PeerId,
    connection_id: ConnectionId,
) -> Option<&mut Peer> {
    match peers.entry(peer_id) {
        Entry::Vacant(entry) => Some(entry.insert(Peer::new(connection_id))),
        Entry::Occupied(entry) => {
            let peer = entry.into_mut();
            match connection_id.cmp(&peer.connection_id) {
                Ordering::Greater => {
                    *peer = Peer::new(connection_id);
                    Some(peer)
                }
                Ordering::Equal => Some(peer),
                Ordering::Less => None,
            }
        }
    }
}

/// Removes `peer_id`, as our subscription stream to it on the connection `connection_id` ended,
/// unless the peer has a newer connection.
///
/// Waggle does not subscribe again on the same connection, so the peer is of no use until it
/// connects again. Removing it drops its sender, which ends its subscription to us too.
fn remove_peer_on_connection(peers: &mut TopicPeers, peer_id: PeerId, connection_id: ConnectionId) {
    if peers
        .get(&peer_id)
        .is_some_and(|peer| peer.connection_id == connection_id)
    {
        peers.remove(&peer_id);
    }
}

struct Payload<E: EthSpec> {
    block_root: Hash256,
    /// The block root as the object ID of our messages about the payload, which share it.
    object_id: Bytes,
    /// Our metadata without requests, encoded, for what we have: the messages that announce the
    /// same to several peers share it.
    announcement: Option<(ChunkBitmap<E>, Bytes)>,
    payload_chunks_root: Hash256,
    slot: Slot,
    chunks: Vec<Chunk<E>>,
    /// When we registered the payload, i.e. received its block. See `REQUEST_DELAY`.
    registered: Instant,
    peers: HashMap<PeerId, PayloadPeer<E>>,
    /// Whether the application has the complete payload, either because it gave it to us or
    /// because we sent it after reconstructing it.
    complete: bool,
    /// Whether we have news for our peers, see
    /// `PayloadDisseminationService::flush_announcements`.
    announcement_pending: bool,
    /// When we last announced what we have to all peers, see `ANNOUNCE_INTERVAL`.
    last_announced: Option<Instant>,
    /// When the first chunk a peer sent us became valid, see `PUSH_PHASE`.
    first_chunk_at: Option<Instant>,
    /// When to try again to request chunks, if a request could not be queued for its peer, see
    /// `REQUEST_RETRY_DELAY`.
    request_retry_at: Option<Instant>,
}

/// A chunk of a payload. We only keep valid chunks, as each chunk is validated on receipt.
#[derive(Clone)]
enum Chunk<E: EthSpec> {
    Unknown {
        /// The peer we last requested the chunk from, and when.
        requested: Option<(PeerId, Instant)>,
    },
    Valid {
        chunk: Arc<PayloadChunk<E>>,
        /// The chunk as we send it, encoded with `encode_chunk`, once we sent it. Kept, as we send
        /// each chunk to several peers, whose messages share it: cloning it does not copy it.
        ///
        /// This is always our own encoding, also of the chunks we received: a peer may compress a
        /// chunk badly on purpose, and forwarding its bytes would pass them on to our peers.
        encoded: Option<Bytes>,
        /// The number of peers we pushed the chunk to, see `PUSH_PEERS`.
        pushes: usize,
    },
}

impl<E: EthSpec> Chunk<E> {
    /// Returns a chunk we don't have and did not request yet.
    fn unknown() -> Self {
        Chunk::Unknown { requested: None }
    }

    /// Returns the valid `chunk`, which was not sent to any peer yet.
    fn valid(chunk: Arc<PayloadChunk<E>>) -> Self {
        Chunk::Valid {
            chunk,
            encoded: None,
            pushes: 0,
        }
    }
}

#[derive(Default)]
struct PayloadPeer<E: EthSpec> {
    /// The chunks the peer last told us it has, if it told us anything yet. Once it did, it tracks
    /// the payload, and we only push chunks to such peers.
    has: Option<ChunkBitmap<E>>,
    sent_to: ChunkBitmap<E>,
    received_from: ChunkBitmap<E>,
    /// The chunks we last told the peer we have, if we told it anything yet.
    announced: Option<ChunkBitmap<E>>,
    /// The number of chunks we pushed to the peer, i.e. sent without it requesting them, which is
    /// limited, see `max_pushes_per_peer`.
    pushes: usize,
    banned: bool,
}

/// A peer that tracks a payload, to push chunks of the payload to, see `Payload::push_chunks`.
struct PushCandidate<'a, E: EthSpec> {
    peer_id: PeerId,
    sender: &'a PieceSender,
    /// The length of the send queue of the peer when we looked, plus what we queued since. Kept
    /// here, as reading it from the queue for every chunk and candidate is slow.
    queued: usize,
    /// The number of chunks we may still push to the peer, see `max_pushes_per_peer`.
    remaining_pushes: usize,
    /// The chunks not to push to the peer: the ones it is known to have, and the ones we tried to
    /// push to it since.
    skip: ChunkBitmap<E>,
}

/// A peer that may be asked for chunks of a payload, see `Payload::request_missing_chunks`.
///
/// What is looked at for every missing chunk and candidate is kept here, as looking it up by
/// peer ID each time is slow.
struct RequestCandidate<'a, E: EthSpec> {
    peer_id: PeerId,
    sender: &'a PieceSender,
    /// The chunks the peer told us it has.
    has: ChunkBitmap<E>,
    /// The number of requests the peer left unanswered, see `Peer::unanswered_requests`.
    unanswered: usize,
    /// The number of requests outstanding with the peer, including the ones of `request`.
    outstanding: usize,
    /// The chunks to request from the peer now.
    request: ChunkBitmap<E>,
}

impl<E: EthSpec> RequestCandidate<'_, E> {
    /// Whether the peer told us that it has the chunk at `index`.
    fn has_chunk(&self, index: usize) -> bool {
        self.has.get(index).unwrap_or(false)
    }
}

impl<E: EthSpec> PayloadPeer<E> {
    /// Whether the peer is known to have the chunk at `index`: it told us it has it, we sent it
    /// the chunk, or it sent us the chunk.
    fn knows(&self, index: usize) -> bool {
        self.has
            .iter()
            .chain([&self.sent_to, &self.received_from])
            .any(|bitmap| bitmap.get(index).unwrap_or(true))
    }

    /// Returns the chunks the peer is known to have, see `knows`, if it tracks the payload.
    fn known_chunks(&self) -> Option<ChunkBitmap<E>> {
        let has = self.has.as_ref()?;
        Some(has.union(&self.sent_to).union(&self.received_from))
    }
}

impl<T: BeaconChainTypes> PayloadDisseminationService<T> {
    /// Spawns the service of the topic of `fork_digest`, which we subscribed to.
    ///
    /// The events of the topic arrive on `topic_events`. The service runs until `unsubscribe`
    /// resolves, and unsubscribes from the topic as it ends. `subscribed_peers` are the peers
    /// that subscribed to the topic before us, with the connections they did so on.
    pub(crate) fn spawn(
        fork_digest: ForkDigest,
        message_recv: mpsc::Receiver<PayloadDisseminationMessage<T::EthSpec>>,
        topic_events: async_channel::Receiver<TopicEvent>,
        unsubscribe: oneshot::Receiver<()>,
        subscribed_peers: HashMap<PeerId, (ConnectionId, PieceSender)>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    ) {
        let peers = subscribed_peers
            .into_iter()
            .map(|(peer_id, (connection_id, sender))| {
                let peer = Peer {
                    sender: Some(sender),
                    ..Peer::new(connection_id)
                };
                (peer_id, peer)
            })
            .collect();

        let executor = network_beacon_processor.executor.clone();
        let service = PayloadDisseminationService {
            fork_digest,
            message_recv,
            topic_events,
            unsubscribe,
            slot_clock: network_beacon_processor.chain.slot_clock.clone(),
            network_beacon_processor,
            // Due right away, which sets the time of the next one.
            next_clean_up: Instant::now(),
            requests_pending: false,
            peers,
            payloads: HashMap::new(),
            unknown_payloads: HashMap::new(),
            previous_payloads: Vec::new(),
        };

        executor.spawn(service.start(), "payload_dissemination");
    }

    async fn start(mut self) {
        let fork_digest = hex::encode(self.fork_digest);
        debug!(fork_digest, "Payload dissemination service starting");

        loop {
            // Yield to the runtime once the budget of the task is used up. Otherwise the task
            // would keep its worker for as long as there are events: taking them uses none of
            // the budget, as `topic_events` is no Tokio channel.
            consume_budget().await;

            let wake_at = self.next_wake(Instant::now());
            let result = select! {
                // Biased, so that chunks are only requested and announcements only made once
                // there is nothing else to do.
                biased;
                // Also resolves if the sender is dropped, which is how we are told to unsubscribe.
                _ = &mut self.unsubscribe => break,
                message = self.message_recv.recv() => {
                    let Some(message) = message else {
                        // Shutting down.
                        break;
                    };
                    self.handle_application_message(message).await
                },
                topic_event = self.topic_events.recv() => {
                    let Ok(topic_event) = topic_event else {
                        // Shutting down.
                        break;
                    };
                    self.handle_waggle_event(topic_event).await
                },
                _ = sleep_until(wake_at) => {
                    self.on_wake();
                    Ok(())
                }
                _ = std::future::ready(()),
                    if self.requests_pending || self.announcements_pending() =>
                {
                    // Requests first: they carry our metadata, which saves announcing it to the
                    // peers we request from.
                    if std::mem::take(&mut self.requests_pending) {
                        self.request_missing_chunks();
                    }
                    self.flush_announcements();
                    Ok(())
                }
            };

            if let Err(err) = result {
                error!(%err, "Error in payload dissemination");
            }
        }
        // Dropping `self.topic_events` unsubscribes from the topic.
        debug!(fork_digest, "Payload dissemination service shutting down");
    }

    /// Returns when there is next something to do that no message or event makes us do, see
    /// `on_wake`: clean up, request chunks, look up an unknown payload, or announce news that is
    /// held back.
    ///
    /// Of what is due already, only what `on_wake` gets done counts. The service would wake up
    /// for anything else over and over.
    fn next_wake(&self, now: Instant) -> Instant {
        let payloads = self
            .payloads
            .values()
            .filter_map(|payload| payload.next_wake(now));
        let lookups = self
            .unknown_payloads
            .values()
            .filter_map(|payload| payload.lookup_at);
        payloads
            .chain(lookups)
            .fold(self.next_clean_up, Instant::min)
    }

    /// Does what is due, see `next_wake`. News that is no longer held back is announced by
    /// `flush_announcements`, once there is nothing else to do.
    fn on_wake(&mut self) {
        let now = Instant::now();
        if now >= self.next_clean_up {
            self.clean_up();
            let disparity = self
                .network_beacon_processor
                .chain
                .spec
                .maximum_gossip_clock_disparity();
            let wait = time_to_next_tracking_window(&self.slot_clock, disparity);
            self.next_clean_up = now.checked_add(wait).unwrap_or(now);
        }
        self.request_missing_chunks();
        self.look_up_unknown_payloads(now);
    }

    async fn handle_application_message(
        &mut self,
        message: PayloadDisseminationMessage<T::EthSpec>,
    ) -> Result<(), Error> {
        match message {
            PayloadDisseminationMessage::PeerSubscribed {
                peer_id,
                connection_id,
                sender,
            } => {
                // If the subscription is of a previous connection, dropping `sender` ends it.
                if let Some(peer) = peer_on_connection(&mut self.peers, peer_id, connection_id) {
                    peer.sender = Some(sender);
                    self.try_inform_new_peer(peer_id);
                }
            }
            PayloadDisseminationMessage::NewPayload(NewPayload {
                payload_chunks_root,
                block_root,
                slot,
                chunks,
            }) => {
                // The block is known now, no need to look it up.
                let unknown_payload = self.unknown_payloads.remove(&block_root);

                // We only track payloads during their tracking window.
                if !self.is_tracked_slot(slot) {
                    return Ok(());
                }

                let payload = self
                    .payloads
                    .entry(block_root)
                    .or_insert_with(|| Payload::new(payload_chunks_root, block_root, slot));
                // The peers that announced the payload already track it, so we may push to them
                // right away.
                if let Some(unknown_payload) = unknown_payload {
                    payload.adopt_unknown(unknown_payload);
                }
                let peers = &self.peers;
                if let Some(chunks) = chunks {
                    if payload.chunks.len() != chunks.len() {
                        return Err(Error::UnexpectedPiecesLen(chunks.len()));
                    }

                    let mut new_chunks = vec![];
                    for (idx, (chunk, new_chunk)) in
                        payload.chunks.iter_mut().zip(chunks).enumerate()
                    {
                        if new_chunk.index as usize != idx {
                            return Err(Error::ChunkIndexMismatch);
                        }
                        if let Chunk::Valid { .. } = chunk {
                            // We already have this chunk, nothing to do.
                            continue;
                        }

                        *chunk = Chunk::valid(new_chunk);
                        new_chunks.push(idx);
                    }

                    // No need to send the completed payload to the app, we got it from there.
                    payload.complete = true;

                    // Peers that don't track the payload yet get the chunks pushed once they tell
                    // us that they do.
                    payload.push_chunks(new_chunks, peers);
                }
                // Tell our peers that we track this payload and what we have, so they tell us what
                // they have, and push chunks to us.
                // This is important, so we do it immediately.
                payload.announce(peers);
            }
        }
        Ok(())
    }

    async fn handle_waggle_event(&mut self, event: TopicEvent) -> Result<(), Error> {
        match event {
            TopicEvent::Opened {
                peer_id,
                connection_id,
            } => {
                if let Some(peer) = peer_on_connection(&mut self.peers, peer_id, connection_id) {
                    peer.subscribed = true;
                    self.try_inform_new_peer(peer_id);
                }
            }
            TopicEvent::Pieces {
                peer_id,
                connection_id,
                pieces,
            } => {
                if self
                    .peers
                    .get(&peer_id)
                    .is_some_and(|peer| peer.connection_id > connection_id)
                {
                    // Sent on a previous connection of the peer, and delivered late. The peer
                    // starts over on its new connection, so this is no longer of use.
                    debug!(%peer_id, "Ignoring waggle message of a previous connection");
                    return Ok(());
                }
                let message = match Message::<T::EthSpec>::try_from(pieces) {
                    Ok(message) => message,
                    Err(err) => {
                        // The peer sent garbage, this is not an error on our side.
                        debug!(%err, %peer_id, "Malformed waggle message");
                        self.penalize_peer(
                            peer_id,
                            None,
                            PeerAction::LowToleranceError,
                            "waggle_malformed_message",
                        );
                        return Ok(());
                    }
                };
                // Whatever the peer tells us may make chunks requestable: it has more chunks, or
                // sent one we requested, so that it can be asked for another.
                self.requests_pending = true;
                self.handle_message(peer_id, message).await?;
            }
            TopicEvent::Closed {
                peer_id,
                connection_id,
            } => {
                remove_peer_on_connection(&mut self.peers, peer_id, connection_id);
            }
        }
        Ok(())
    }

    async fn handle_message(
        &mut self,
        peer_id: PeerId,
        message: Message<T::EthSpec>,
    ) -> Result<(), Error> {
        if let Some(payload) = self.payloads.get_mut(&message.block_root) {
            let peer = payload.peers.entry(peer_id).or_default();
            if peer.banned {
                debug!("Message from banned peer");
                return Ok(());
            }

            let carried_chunk = message.chunk.is_some();
            if let Some(message_chunk) = message.chunk {
                if peer
                    .received_from
                    .get(message_chunk.index as usize)
                    .unwrap_or(true)
                {
                    // This peer sent this chunk already, or it is out of bounds.
                    self.penalize_peer(
                        peer_id,
                        Some(message.block_root),
                        PeerAction::MidToleranceError,
                        "waggle_duplicate_chunk",
                    );
                    return Ok(());
                } else if let Some(local_chunk) =
                    payload.chunks.get_mut(message_chunk.index as usize)
                {
                    let _ = peer.received_from.set(message_chunk.index as usize, true);

                    let valid = match local_chunk {
                        Chunk::Valid { chunk, .. } => *chunk == message_chunk,
                        // The index is in bounds, as `verify_inclusion_proof` requires.
                        Chunk::Unknown { .. } => {
                            message_chunk.verify_inclusion_proof(payload.payload_chunks_root)
                        }
                    };
                    if !valid {
                        self.penalize_peer(
                            peer_id,
                            Some(message.block_root),
                            PeerAction::LowToleranceError,
                            "waggle_invalid_chunk",
                        );
                        return Ok(());
                    }

                    if let Chunk::Unknown { requested } = local_chunk {
                        // The peer we requested the chunk from, if it left the request
                        // unanswered and another peer sent the chunk.
                        let request_timeout = request_timeout(message_chunk.chunk.len());
                        let unanswered_by = requested
                            .filter(|(requested_from, requested_at)| {
                                *requested_from != peer_id
                                    && requested_at.elapsed() >= request_timeout
                            })
                            .map(|(requested_from, _)| requested_from);
                        if let Some(peer) = unanswered_by.and_then(|peer| self.peers.get_mut(&peer))
                        {
                            peer.request_timed_out();
                        }
                        if let Some(peer) = self.peers.get_mut(&peer_id) {
                            peer.sent_new_chunk();
                        }
                        *local_chunk = Chunk::valid(message_chunk.clone());
                        payload.on_chunk_valid(
                            message_chunk.index as usize,
                            &self.peers,
                            &self.network_beacon_processor,
                        );
                    }
                } else {
                    // We should be always able to take the previous branch as we preinitialize
                    // the chunk vector.
                    return Err(Error::ChunkOutOfBounds);
                }
            }

            if let Some(metadata) = message.metadata {
                let peer = payload.peers.entry(peer_id).or_default();
                if metadata.slot != payload.slot {
                    // The claimed slot is incorrect.
                    self.penalize_peer(
                        peer_id,
                        Some(message.block_root),
                        PeerAction::LowToleranceError,
                        "waggle_wrong_slot",
                    );
                    return Ok(());
                }
                if let Some(has) = &peer.has
                    && !has.difference(&metadata.have).is_zero()
                {
                    // Peer has lost some part.
                    self.penalize_peer(
                        peer_id,
                        Some(message.block_root),
                        PeerAction::MidToleranceError,
                        "waggle_lost_chunk",
                    );
                    return Ok(());
                }

                // The peer dropped what we told it before it tracked the payload, so tell it
                // again.
                let first_metadata = peer.has.is_none();
                if first_metadata {
                    peer.announced = None;
                }
                peer.has = Some(metadata.have.clone());

                // Fulfill any request immediately.
                let mut send = Vec::new();
                for ((((requested, has), sent_to), received_from), chunk) in metadata
                    .request
                    .iter()
                    .zip(metadata.have.iter())
                    .zip(peer.sent_to.iter())
                    .zip(peer.received_from.iter())
                    .zip(payload.chunks.iter())
                // beautiful
                {
                    if requested {
                        if has || received_from {
                            // Peer requests something they have.
                            self.penalize_peer(
                                peer_id,
                                Some(message.block_root),
                                PeerAction::MidToleranceError,
                                "waggle_request_for_held_chunk",
                            );
                            return Ok(());
                        }
                        // We never send a peer a chunk twice. Peers can't have dropped what we
                        // pushed, as we only push to peers that track the payload.
                        if let Chunk::Valid { chunk, .. } = chunk
                            && !sent_to
                        {
                            send.push(chunk.index as usize);
                        }
                    }
                }

                if !send.is_empty()
                    && let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender)
                {
                    let have = payload.have();
                    for index in send {
                        if !payload.send_chunk(index, peer_id, sender, &have) {
                            break;
                        }
                    }
                }

                // Tell the peer what we have if it doesn't know yet.
                if carried_chunk && !first_metadata {
                    // The peer is pushing chunks, each with its new metadata. Answering each of
                    // them would defeat coalescing our announcements, so leave it to the next
                    // flush.
                    payload.announcement_pending = true;
                } else if let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender) {
                    let have = payload.have();
                    payload.announce_to(peer_id, sender, &have);
                }

                // The peer tracks the payload now, so we may push to it the chunks that we didn't
                // push to enough peers yet.
                if first_metadata {
                    payload.push_pending_chunks(&self.peers);
                }
            }
        } else if let Some(chunk) = message.chunk {
            // Peers only send us chunks of payloads we told them about, which we only do while we
            // track the payload. So this is no chunk we could have asked for, unless it was sent
            // before we stopped tracking the payload.
            let tracked_until_recently = self
                .previous_payloads
                .iter()
                .any(|(block_root, _)| *block_root == message.block_root);
            debug!(
                %peer_id,
                block_root = %message.block_root,
                index = chunk.index,
                tracked_until_recently,
                "Dropping chunk of untracked payload"
            );
            if !tracked_until_recently {
                self.penalize_peer(
                    peer_id,
                    None,
                    PeerAction::HighToleranceError,
                    "waggle_chunk_of_untracked_payload",
                );
            }
        } else if let Some(metadata) = message.metadata {
            // Metadata about a payload we don't track is expected, as peers announce the payloads
            // they track to all peers. We remember who announced it and what they have, to look up
            // the block if it doesn't reach us, and to know what our peers have once we track the
            // payload. Requests are ignored: we have nothing to serve.
            //
            // This is bounded, so peers can't rely on it: we tell the peer about the payload once
            // we track it, and the peer then sends its metadata again.
            if !self.is_tracked_slot(metadata.slot) {
                debug!(
                    %peer_id,
                    block_root = %message.block_root,
                    slot = %metadata.slot,
                    "Ignoring announcement of unknown payload outside its tracking window"
                );
            } else if !note_unknown_payload(
                &mut self.unknown_payloads,
                peer_id,
                message.block_root,
                metadata,
                Instant::now(),
            ) {
                // The peer announced more unknown payloads than we remember per peer. It is not
                // penalized: the bound is ours, and the peer may track all of them.
                debug!(
                    %peer_id,
                    block_root = %message.block_root,
                    "Ignoring announcement of too many unknown payloads"
                );
            }
        }
        Ok(())
    }

    /// Looks up the blocks of payloads that peers announced `UNKNOWN_PAYLOAD_LOOKUP_DELAY`
    /// before `now`, which we still don't track.
    fn look_up_unknown_payloads(&mut self, now: Instant) {
        for (block_root, payload) in &mut self.unknown_payloads {
            if payload.lookup_at.is_none_or(|lookup_at| now < lookup_at) {
                continue;
            }
            payload.lookup_at = None;
            debug!(%block_root, "Looking up block of unknown payload");
            for peer_id in payload.peers.keys() {
                // Nothing to do on error, sync is shutting down.
                let _ = self.network_beacon_processor.sync_tx.send(
                    SyncMessage::UnknownBlockHashFromAttestation(*peer_id, *block_root),
                );
            }
        }
    }

    /// Returns the slots whose payloads are in their tracking window, see `tracked_slots`.
    fn tracked_slots(&self) -> Option<RangeInclusive<Slot>> {
        let disparity = self
            .network_beacon_processor
            .chain
            .spec
            .maximum_gossip_clock_disparity();
        tracked_slots(&self.slot_clock, disparity)
    }

    /// Whether a payload of `slot` is in its tracking window.
    fn is_tracked_slot(&self, slot: Slot) -> bool {
        self.tracked_slots()
            .is_some_and(|tracked_slots| tracked_slots.contains(&slot))
    }

    /// Stops tracking payloads, and forgets the unknown ones, once their tracking window is over,
    /// and drops the peers neither of whose subscriptions is alive anymore.
    ///
    /// The payloads we stop tracking are remembered as `previous_payloads` for another
    /// `PREVIOUS_PAYLOAD_SLOTS` slots.
    ///
    /// This is done whenever the tracking window moved on, see `time_to_next_tracking_window`,
    /// as a window that is over is all there is to clean up for. The peers are dropped along
    /// with it: until then, they are of no harm, as nothing is sent to them.
    fn clean_up(&mut self) {
        let tracked_slots = self.tracked_slots();
        let is_tracked = |slot: &Slot| {
            tracked_slots
                .as_ref()
                .is_some_and(|tracked_slots| tracked_slots.contains(slot))
        };
        let previous_payloads = &mut self.previous_payloads;
        self.payloads.retain(|block_root, payload| {
            let tracked = is_tracked(&payload.slot);
            if !tracked {
                previous_payloads.push((*block_root, payload.slot));
            }
            tracked
        });
        // A payload stays a previous one for as long as it would be tracked if it were of a slot
        // `PREVIOUS_PAYLOAD_SLOTS` later.
        previous_payloads
            .retain(|(_, slot)| is_tracked(&slot.saturating_add(PREVIOUS_PAYLOAD_SLOTS)));
        self.unknown_payloads.retain(|_, payload| {
            payload
                .peers
                .retain(|_, metadata| is_tracked(&metadata.slot));
            !payload.peers.is_empty()
        });

        self.peers.retain(|_, peer| {
            // The subscription of the peer to us ended. It may subscribe again.
            if peer.sender.as_ref().is_some_and(PieceSender::is_closed) {
                peer.sender = None;
            }
            peer.keep()
        });
    }

    fn try_inform_new_peer(&mut self, peer_id: PeerId) {
        let Some(sender) = self.peers.get(&peer_id).and_then(Peer::sender) else {
            // This peer either has no sender yet or the sub isn't yet mutual.
            return;
        };
        for payload in self.payloads.values_mut() {
            // The peer may have reconnected, and forgotten what we told it.
            if let Some(payload_peer) = payload.peers.get_mut(&peer_id) {
                payload_peer.announced = None;
            }
            let have = payload.have();
            payload.announce_to(peer_id, sender, &have);
        }
        // The peer may have chunks we lack, as it told us before or while the payload was unknown.
        self.requests_pending = true;
    }

    /// Whether any payload has news for our peers that is due to be announced.
    fn announcements_pending(&self) -> bool {
        let now = Instant::now();
        self.payloads
            .values()
            .any(|payload| payload.announcement_pending && payload.announcement_due(now))
    }

    /// Announces the payloads with news to our peers.
    ///
    /// Announcing as soon as a chunk becomes valid would send a message per chunk to every peer,
    /// filling their send queues. Instead, we wait until there is nothing else to do, which
    /// coalesces the announcements of chunks received in a burst.
    ///
    /// News that is not due yet, see `Payload::announcement_due`, is held back until it is. The
    /// service wakes up for it by then, see `next_wake`.
    fn flush_announcements(&mut self) {
        let now = Instant::now();
        for payload in self.payloads.values_mut() {
            if payload.announcement_pending && payload.announcement_due(now) {
                payload.announcement_pending = false;
                payload.last_announced = Some(now);
                payload.announce(&self.peers);
            }
        }
    }

    /// Requests the chunks we lack of the payloads registered at least `REQUEST_DELAY` ago, see
    /// `Payload::request_missing_chunks`.
    ///
    /// Chunks become requestable as time passes, which the service wakes up for, see
    /// `Payload::next_request_at`, or as peers tell us more, see `requests_pending`.
    fn request_missing_chunks(&mut self) {
        let now = Instant::now();
        for payload in self.payloads.values_mut() {
            payload.request_missing_chunks(&mut self.peers, now);
        }
    }

    /// Reports `peer_id` to the peer manager, and ignores it for the rest of the payload of
    /// `block_root`, if any.
    fn penalize_peer(
        &mut self,
        peer_id: PeerId,
        block_root: Option<Hash256>,
        action: PeerAction,
        msg: &'static str,
    ) {
        if let Some(block_root) = block_root
            && let Some(payload) = self.payloads.get_mut(&block_root)
        {
            payload.peers.entry(peer_id).or_default().banned = true;
            // Request the chunks we requested from the peer elsewhere.
            for chunk in &mut payload.chunks {
                if let Chunk::Unknown { requested } = chunk
                    && requested.is_some_and(|(requested_from, _)| requested_from == peer_id)
                {
                    *requested = None;
                }
            }
        };
        // Nothing to do on error, the network service is shutting down.
        let _ = self
            .network_beacon_processor
            .network_tx
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::Waggle,
                msg,
            });
    }
}

/// Returns how long to wait for a requested chunk of a payload whose chunks are `chunk_len`
/// bytes long: `REQUEST_TIMEOUT`, and `REQUEST_TIMEOUT_PER_BYTE` for every byte.
fn request_timeout(chunk_len: usize) -> Duration {
    let chunk_len = u32::try_from(chunk_len).unwrap_or(u32::MAX);
    REQUEST_TIMEOUT.saturating_add(REQUEST_TIMEOUT_PER_BYTE.saturating_mul(chunk_len))
}

/// Returns the maximum number of chunks of a payload to push to one peer, if we could push to
/// `peer_count` peers once they track the payload: `MAX_PUSH_SHARE` times what each of them would
/// get if we spread our pushes, `PUSH_PEERS` per chunk, evenly over them.
///
/// With few peers, this is more than a payload has chunks, and so no limit.
fn max_pushes_per_peer<E: EthSpec>(peer_count: usize) -> usize {
    E::total_execution_payload_chunks()
        .saturating_mul(PUSH_PEERS)
        .saturating_mul(MAX_PUSH_SHARE)
        .div_ceil(peer_count.max(1))
}

/// Returns the slots whose payloads are in their tracking window, if the slot clock works: the
/// current slot and the `TRACKED_SLOTS_AFTER_OWN` slots before it, allowing for a clock disparity
/// of `disparity`.
fn tracked_slots(slot_clock: &impl SlotClock, disparity: Duration) -> Option<RangeInclusive<Slot>> {
    let earliest_current_slot = slot_clock.now_with_past_tolerance(disparity)?;
    let latest_current_slot = slot_clock.now_with_future_tolerance(disparity)?;
    Some(earliest_current_slot.saturating_sub(TRACKED_SLOTS_AFTER_OWN)..=latest_current_slot)
}

/// Returns how long it takes until the tracking window moves on, i.e. until the first of the
/// `tracked_slots` is over: until the next slot starts, allowing for a clock disparity of
/// `disparity`. A slot, if the slot clock doesn't work.
fn time_to_next_tracking_window(slot_clock: &impl SlotClock, disparity: Duration) -> Duration {
    let time_to_next_window = || {
        let earliest_current_slot = slot_clock.now_with_past_tolerance(disparity)?;
        slot_clock
            .start_of(earliest_current_slot.saturating_add(1u64))?
            .checked_add(disparity)?
            .checked_sub(slot_clock.now_duration()?)
    };
    time_to_next_window().unwrap_or_else(|| slot_clock.slot_duration())
}

/// Records that `peer_id` sent `metadata` about the payload of `block_root`, which we don't
/// track. Returns whether it was recorded.
///
/// A peer may have announced `MAX_UNKNOWN_PAYLOADS_PER_PEER` unknown payloads at a time: the ones
/// we track by now or whose tracking window is over don't count. It may announce each of them again as it
/// gets more chunks, of which we keep the latest.
fn note_unknown_payload<E: EthSpec>(
    unknown_payloads: &mut HashMap<Hash256, UnknownPayload<E>>,
    peer_id: PeerId,
    block_root: Hash256,
    metadata: ChunkMetadata<E>,
    now: Instant,
) -> bool {
    let announced_others = unknown_payloads
        .iter()
        .filter(|(other_root, payload)| {
            **other_root != block_root && payload.peers.contains_key(&peer_id)
        })
        .count();
    if announced_others >= MAX_UNKNOWN_PAYLOADS_PER_PEER {
        return false;
    }
    unknown_payloads
        .entry(block_root)
        .or_insert_with(|| UnknownPayload {
            peers: HashMap::new(),
            lookup_at: now.checked_add(UNKNOWN_PAYLOAD_LOOKUP_DELAY),
        })
        .peers
        .insert(peer_id, metadata);
    true
}

impl<E: EthSpec> Payload<E> {
    fn new(payload_chunks_root: Hash256, block_root: Hash256, slot: Slot) -> Self {
        Payload {
            block_root,
            object_id: Bytes::copy_from_slice(block_root.as_slice()),
            announcement: None,
            payload_chunks_root,
            slot,
            chunks: vec![Chunk::unknown(); E::total_execution_payload_chunks()],
            registered: Instant::now(),
            peers: HashMap::new(),
            complete: false,
            announcement_pending: false,
            last_announced: None,
            first_chunk_at: None,
            request_retry_at: None,
        }
    }

    /// Whether what we have may be announced to all peers at `now`: `ANNOUNCE_INTERVAL` after
    /// the last time, or right away if we have every chunk, so that peers stop sending us any.
    fn announcement_due(&self, now: Instant) -> bool {
        self.complete
            || self
                .last_announced
                .is_none_or(|last| now.saturating_duration_since(last) >= ANNOUNCE_INTERVAL)
    }

    /// Returns when the service is to wake up for the payload after `now`, if nothing else
    /// happens, see `PayloadDisseminationService::next_wake`: to announce news that is held
    /// back, or to request chunks.
    fn next_wake(&self, now: Instant) -> Option<Instant> {
        let announce_at = self
            .last_announced
            .filter(|_| self.announcement_pending && !self.announcement_due(now))
            .and_then(|last| last.checked_add(ANNOUNCE_INTERVAL));
        [announce_at, self.next_request_at(now)]
            .into_iter()
            .flatten()
            .min()
    }

    /// Returns when `request_missing_chunks` is next to be called after `now`, if no peer tells
    /// us anything until then: once `REQUEST_DELAY` passed, and from then on whenever a request
    /// times out, or is to be tried again as it could not be queued.
    ///
    /// A chunk whose request timed out and that no peer can be asked for is requested once a
    /// peer tells us more, so there is nothing to wake up for.
    fn next_request_at(&self, now: Instant) -> Option<Instant> {
        if self.complete {
            return None;
        }
        let request_at = self.registered.checked_add(REQUEST_DELAY)?;
        if now < request_at {
            return Some(request_at);
        }
        let request_timeout = self.request_timeout();
        self.chunks
            .iter()
            .filter_map(|chunk| match chunk {
                Chunk::Unknown {
                    requested: Some((_, requested_at)),
                } => requested_at.checked_add(request_timeout),
                _ => None,
            })
            .chain(self.request_retry_at)
            .filter(|at| *at > now)
            .min()
    }

    /// Takes over what the peers that announced the payload before we tracked it told us they
    /// have. They track the payload, so chunks may be pushed to them without waiting for them to
    /// send their metadata again.
    ///
    /// Peers that claimed the wrong slot are not taken over. They are penalized if they claim it
    /// again, now that we know better.
    fn adopt_unknown(&mut self, unknown_payload: UnknownPayload<E>) {
        for (peer_id, metadata) in unknown_payload.peers {
            if metadata.slot != self.slot {
                continue;
            }
            let payload_peer = self.peers.entry(peer_id).or_default();
            // Whatever the peer told us since we track the payload is newer.
            payload_peer.has.get_or_insert(metadata.have);
        }
    }

    /// Returns the chunks we have, i.e. the valid ones.
    fn have(&self) -> ChunkBitmap<E> {
        let mut have = ChunkBitmap::<E>::new();
        for (idx, chunk) in self.chunks.iter().enumerate() {
            // Can't fail, we have exactly as many chunks as bits.
            let _ = have.set(idx, matches!(chunk, Chunk::Valid { .. }));
        }
        have
    }

    /// Returns all chunks if every one of them is valid.
    fn valid_chunks(&self) -> Option<Vec<Arc<PayloadChunk<E>>>> {
        self.chunks
            .iter()
            .map(|chunk| match chunk {
                Chunk::Valid { chunk, .. } => Some(chunk.clone()),
                Chunk::Unknown { .. } => None,
            })
            .collect()
    }

    /// Disseminates the chunk at `index`, which just became valid, and hands the payload to the
    /// beacon processor once every chunk is valid.
    fn on_chunk_valid<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        index: usize,
        peers: &HashMap<PeerId, Peer>,
        network_beacon_processor: &Arc<NetworkBeaconProcessor<T>>,
    ) {
        self.first_chunk_at.get_or_insert_with(Instant::now);
        self.push_chunk(index, peers);
        self.announcement_pending = true;

        if !self.complete
            && let Some(chunks) = self.valid_chunks()
        {
            // We are complete, send to the beacon processor for reconstruction.
            self.complete = true;
            if let Err(err) = network_beacon_processor.send_reassembled_execution_payload(
                self.block_root,
                self.slot,
                self.payload_chunks_root,
                chunks,
            ) {
                warn!(
                    %err,
                    block_root = %self.block_root,
                    "Unable to send reassembled payload to the beacon processor"
                );
            }
        }
    }

    /// Returns the valid chunk at `index`, encoded with `encode_chunk`.
    ///
    /// The chunk is encoded when it is first sent, and the encoding kept with it.
    fn encoded_chunk(&mut self, index: usize) -> Option<Bytes> {
        let Some(Chunk::Valid { chunk, encoded, .. }) = self.chunks.get_mut(index) else {
            return None;
        };
        if encoded.is_none() {
            match encode_chunk(chunk) {
                Ok(encoded_chunk) => *encoded = Some(encoded_chunk.into()),
                Err(err) => {
                    error!(
                        ?err,
                        block_root = %self.block_root,
                        index,
                        "Unable to encode payload chunk"
                    );
                    return None;
                }
            }
        }
        encoded.clone()
    }

    /// Queues a message about the payload for `peer_id`, and returns whether it was queued: the
    /// valid chunk at `chunk`, if any, and our metadata, i.e. that we have `have`, which is what
    /// we have now, and that we request the chunks of `request`, if any.
    ///
    /// The metadata is left out if it is no news to the peer: it knows that we have `have`, and
    /// we request nothing. `kind` is what the message is for, to tell the send errors apart.
    fn send(
        &mut self,
        peer_id: PeerId,
        sender: &PieceSender,
        have: &ChunkBitmap<E>,
        request: Option<&ChunkBitmap<E>>,
        chunk: Option<usize>,
        kind: &'static str,
    ) -> bool {
        let encoded_chunk = match chunk {
            Some(index) => match self.encoded_chunk(index) {
                Some(encoded_chunk) => Some(encoded_chunk),
                None => return false,
            },
            None => None,
        };
        let payload_peer = self.peers.entry(peer_id).or_default();

        let announce = request.is_some() || payload_peer.announced.as_ref() != Some(have);
        // Like gossipsub control messages, the metadata is not compressed, as it is too small to
        // benefit.
        let metadata = announce.then(|| match (request, &self.announcement) {
            // What we announced to another peer already.
            (None, Some((announced, metadata))) if announced == have => metadata.clone(),
            _ => {
                let metadata = ChunkMetadata::<E> {
                    slot: self.slot,
                    have: have.clone(),
                    request: request.cloned().unwrap_or_else(ChunkBitmap::<E>::new),
                };
                let metadata = Bytes::from(metadata.as_ssz_bytes());
                if request.is_none() {
                    self.announcement = Some((have.clone(), metadata.clone()));
                }
                metadata
            }
        });
        let message = ObjectPieces {
            object_id: self.object_id.clone(),
            metadata,
            pieces: encoded_chunk,
        };
        if let Err(err) = sender.try_send(message) {
            debug!(%err, %peer_id, kind, index = ?chunk, "Unable to send message");
            return false;
        }

        if let Some(index) = chunk {
            let _ = payload_peer.sent_to.set(index, true);
        }
        if announce {
            payload_peer.announced = Some(have.clone());
        }
        true
    }

    /// Sends the valid chunk at `index` to `peer_id`, and returns whether it was queued for
    /// sending.
    ///
    /// Our metadata is sent along if the peer doesn't know that we have `have`, which is what we
    /// have now. This saves announcing it in a message of its own. It carries no requests, those
    /// are made by `request_missing_chunks`.
    fn send_chunk(
        &mut self,
        index: usize,
        peer_id: PeerId,
        sender: &PieceSender,
        have: &ChunkBitmap<E>,
    ) -> bool {
        self.send(peer_id, sender, have, None, Some(index), "chunk")
    }

    /// Pushes the valid chunk at `index` to peers that track the payload and aren't known to have
    /// the chunk, until it was pushed to `PUSH_PEERS` peers, preferring peers with a short send
    /// queue. No peer gets more of the payload's chunks pushed than `max_pushes_per_peer`.
    ///
    /// Peers track the payload once they sent metadata about it. If too few of them can be
    /// pushed to yet, the remaining pushes are made as more of them track the payload, see
    /// `push_pending_chunks`.
    fn push_chunk(&mut self, index: usize, peers: &TopicPeers) {
        self.push_chunks(vec![index], peers);
    }

    /// Pushes the valid chunks at `indices` like `push_chunk`, one peer at a time: every chunk is
    /// pushed to a first peer before any is pushed to a second one. The chunks pushed to the
    /// fewest peers so far go first, in random order among them.
    ///
    /// The send queue of a peer is sent in order. Pushing one chunk to all of its peers before
    /// the next would queue the chunks in the same order for every peer, and the last one would
    /// leave us only after all the others did, to every peer. A payload is only of use with all
    /// of its chunks, so it would reach the network as late as possible. For the same reason, a
    /// peer that may only get some of the chunks gets the ones we pushed the least.
    fn push_chunks(&mut self, mut indices: Vec<usize>, peers: &TopicPeers) {
        // Past the time we push the chunks we received for, see `PUSH_PHASE`.
        if let Some(first_chunk_at) = self.first_chunk_at
            && first_chunk_at.elapsed() >= PUSH_PHASE
        {
            return;
        }
        indices.retain(|index| {
            matches!(
                self.chunks.get(*index),
                Some(Chunk::Valid { pushes, .. }) if *pushes < PUSH_PEERS
            )
        });
        if indices.is_empty() {
            return;
        }

        // The peers we could push to once they track the payload share our pushes.
        let peer_count = peers
            .values()
            .filter(|peer| peer.sender().is_some())
            .count();
        let max_pushes = max_pushes_per_peer::<E>(peer_count);

        // Look up the peers that track the payload once, rather than for every push.
        let single_index = match indices.as_slice() {
            [index] => Some(*index),
            _ => None,
        };
        let mut candidates = peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                let sender = peer.sender()?;
                let payload_peer = self.peers.get(peer_id)?;
                if payload_peer.banned {
                    return None;
                }
                let remaining_pushes = max_pushes.saturating_sub(payload_peer.pushes);
                if remaining_pushes == 0 {
                    return None;
                }
                let skip = match single_index {
                    // A single chunk is checked right away, which spares collecting what the
                    // peer knows. This is the common case: a chunk we received.
                    Some(index) => {
                        payload_peer.has.as_ref()?;
                        if payload_peer.knows(index) {
                            return None;
                        }
                        ChunkBitmap::<E>::new()
                    }
                    None => payload_peer.known_chunks()?,
                };
                Some(PushCandidate {
                    peer_id: *peer_id,
                    sender,
                    queued: sender.len(),
                    remaining_pushes,
                    skip,
                })
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return;
        }
        // Random order, so that ties between peers with equally long send queues are broken
        // randomly.
        let mut rng = rand::rng();
        candidates.shuffle(&mut rng);

        let have = self.have();
        for _ in 0..PUSH_PEERS {
            // The chunks pushed to the fewest peers first, in random order among them.
            indices.shuffle(&mut rng);
            let chunks = &self.chunks;
            indices.sort_by_key(|index| match chunks.get(*index) {
                Some(Chunk::Valid { pushes, .. }) => *pushes,
                _ => usize::MAX,
            });
            // A chunk that can't be pushed to another peer now can't be later in this call.
            indices.retain(|index| self.push_chunk_to_one(*index, &mut candidates, &have));
            if indices.is_empty() {
                break;
            }
        }
    }

    /// Pushes the valid chunk at `index` to the candidate with the shortest send queue that may
    /// get another push, unless the chunk was pushed to `PUSH_PEERS` peers already. Returns
    /// whether it was pushed.
    fn push_chunk_to_one(
        &mut self,
        index: usize,
        candidates: &mut [PushCandidate<'_, E>],
        have: &ChunkBitmap<E>,
    ) -> bool {
        if !matches!(
            self.chunks.get(index),
            Some(Chunk::Valid { pushes, .. }) if *pushes < PUSH_PEERS
        ) {
            return false;
        }

        loop {
            // The first of the candidates with the shortest queue, which are in random order.
            let Some(candidate) = candidates
                .iter_mut()
                .filter(|candidate| {
                    candidate.remaining_pushes > 0 && !candidate.skip.get(index).unwrap_or(true)
                })
                .min_by_key(|candidate| candidate.queued)
            else {
                return false;
            };
            let _ = candidate.skip.set(index, true);
            // If the chunk can't be sent to the peer, it is pushed to another one instead.
            if self.send_chunk(index, candidate.peer_id, candidate.sender, have) {
                candidate.queued = candidate.queued.saturating_add(1);
                candidate.remaining_pushes = candidate.remaining_pushes.saturating_sub(1);
                if let Some(payload_peer) = self.peers.get_mut(&candidate.peer_id) {
                    payload_peer.pushes = payload_peer.pushes.saturating_add(1);
                }
                if let Some(Chunk::Valid { pushes, .. }) = self.chunks.get_mut(index) {
                    *pushes = pushes.saturating_add(1);
                }
                return true;
            }
        }
    }

    /// Pushes the valid chunks that were not pushed to `PUSH_PEERS` peers yet, as too few peers
    /// tracked the payload so far, see `push_chunks`.
    fn push_pending_chunks(&mut self, peers: &TopicPeers) {
        self.push_chunks((0..self.chunks.len()).collect(), peers);
    }

    /// Announces our metadata to every peer we are mutually subscribed with, see `announce_to`.
    fn announce(&mut self, peers: &TopicPeers) {
        let have = self.have();
        for (peer_id, peer) in peers {
            if let Some(sender) = peer.sender() {
                self.announce_to(*peer_id, sender, &have);
            }
        }
    }

    /// Sends our metadata to `peer_id`, unless it knows already that we have `have`, which is what
    /// we have now. It carries no requests, those are made by `request_missing_chunks`.
    fn announce_to(&mut self, peer_id: PeerId, sender: &PieceSender, have: &ChunkBitmap<E>) {
        let payload_peer = self.peers.entry(peer_id).or_default();
        if payload_peer.banned || payload_peer.announced.as_ref() == Some(have) {
            return;
        }

        // Nothing to do on error: If closed, it will be cleaned up. If full, the peer is told
        // along with our next news.
        self.send(peer_id, sender, have, None, None, "announcement");
    }

    /// How long to wait for a requested chunk before requesting it again, see
    /// `request_timeout`. The chunks of a payload are equally long, but for the last ones, which
    /// can be shorter. Until we have one of them, the chunks count as empty.
    fn request_timeout(&self) -> Duration {
        let chunk_len = self
            .chunks
            .iter()
            .filter_map(|chunk| match chunk {
                Chunk::Valid { chunk, .. } => Some(chunk.chunk.len()),
                Chunk::Unknown { .. } => None,
            })
            .max()
            .unwrap_or_default();
        request_timeout(chunk_len)
    }

    /// Requests the chunks we lack from the peers that have them, if we registered the payload at
    /// least `REQUEST_DELAY` before `now`.
    ///
    /// Each chunk is requested from one peer, and again once it was not received within the
    /// timeout, see `request_timeout`, from another peer if one has it. The request then counts
    /// as left unanswered by the peer it was made to.
    ///
    /// No peer is asked beyond `MAX_REQUESTS_PER_PEER` outstanding requests, and none that left
    /// `MAX_UNANSWERED_REQUESTS` unanswered. Among the peers that have a chunk, the one that left
    /// the fewest requests unanswered is asked, and of those the one with the fewest outstanding
    /// requests, which spreads the requests. The chunks that the fewest peers have are requested
    /// first.
    ///
    /// A request is our metadata with the requested chunks set, so it tells the peer what we have
    /// as well. If it can't be queued for the peer, it is tried again after `REQUEST_RETRY_DELAY`.
    fn request_missing_chunks(&mut self, peers: &mut TopicPeers, now: Instant) {
        if now.saturating_duration_since(self.registered) < REQUEST_DELAY {
            return;
        }
        self.request_retry_at = None;

        let request_timeout = self.request_timeout();
        // The chunks to request, and the number of requests outstanding with each peer.
        let mut missing = vec![];
        let mut outstanding = HashMap::<PeerId, usize>::new();
        for (index, chunk) in self.chunks.iter().enumerate() {
            let Chunk::Unknown { requested } = chunk else {
                continue;
            };
            match requested {
                Some((peer_id, requested_at))
                    if now.saturating_duration_since(*requested_at) < request_timeout =>
                {
                    let requests = outstanding.entry(*peer_id).or_default();
                    *requests = requests.saturating_add(1);
                }
                _ => missing.push(index),
            }
        }
        if missing.is_empty() {
            return;
        }
        let mut missing_chunks = ChunkBitmap::<E>::new();
        for index in &missing {
            let _ = missing_chunks.set(*index, true);
        }

        // Look up the peers that can be asked once, rather than for every chunk.
        let mut candidates = peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                let sender = peer.sender()?;
                let payload_peer = self.peers.get(peer_id)?;
                // Peers that left too many requests unanswered are not asked. Among the others,
                // the ones that left the fewest unanswered are asked first.
                let unanswered = peer.unanswered_requests;
                if payload_peer.banned || unanswered >= MAX_UNANSWERED_REQUESTS {
                    return None;
                }
                // A peer that told us nothing yet has no chunk to ask for. Most peers have none
                // of the chunks to request while a payload is new, or once few are left to get.
                let has = payload_peer.has.as_ref()?;
                if has.intersection(&missing_chunks).is_zero() {
                    return None;
                }
                Some(RequestCandidate::<E> {
                    peer_id: *peer_id,
                    sender,
                    has: has.clone(),
                    unanswered,
                    outstanding: outstanding.get(peer_id).copied().unwrap_or_default(),
                    request: ChunkBitmap::<E>::new(),
                })
            })
            .collect::<Vec<_>>();
        // Usually, every peer that has chunks we lack is busy with a request, as this is called
        // whenever a peer told us anything.
        if candidates
            .iter()
            .all(|candidate| candidate.outstanding >= MAX_REQUESTS_PER_PEER)
        {
            return;
        }
        // Random order, so that ties between peers and between chunks are broken randomly.
        candidates.shuffle(&mut rand::rng());
        missing.shuffle(&mut rand::rng());
        // Request the chunks first that the fewest peers have. Otherwise, a peer that has them
        // could be asked for chunks that other peers have too, and have no requests left.
        missing.sort_by_cached_key(|index| {
            candidates
                .iter()
                .filter(|candidate| candidate.has_chunk(*index))
                .count()
        });

        for index in missing {
            // The peer that did not send the chunk in time, if we requested it before.
            let timed_out = match self.chunks.get(index) {
                Some(Chunk::Unknown {
                    requested: Some((peer_id, _)),
                }) => Some(*peer_id),
                _ => None,
            };
            let chosen = candidates
                .iter_mut()
                .filter(|candidate| {
                    candidate.outstanding < MAX_REQUESTS_PER_PEER && candidate.has_chunk(index)
                })
                .min_by_key(|candidate| {
                    (
                        Some(candidate.peer_id) == timed_out,
                        candidate.unanswered,
                        candidate.outstanding,
                    )
                });
            let Some(candidate) = chosen else {
                continue;
            };
            candidate.outstanding = candidate.outstanding.saturating_add(1);
            let _ = candidate.request.set(index, true);
        }

        let have = self.have();
        // The peers that let the previous request of a chunk we request again time out.
        let mut unanswered_by = vec![];
        for candidate in &candidates {
            let (peer_id, request) = (candidate.peer_id, &candidate.request);
            if request.is_zero() {
                continue;
            }
            if !self.send(
                peer_id,
                candidate.sender,
                &have,
                Some(request),
                None,
                "request",
            ) {
                // No peer tells us once the queue has room again, so try again in a while.
                self.request_retry_at = now.checked_add(REQUEST_RETRY_DELAY);
                continue;
            }
            for (requested, chunk) in request.iter().zip(&mut self.chunks) {
                if requested
                    && let Chunk::Unknown {
                        requested: previous_request,
                    } = chunk
                {
                    // A chunk is only requested again once its previous request timed out.
                    if let Some((previous_peer, _)) = previous_request {
                        unanswered_by.push(*previous_peer);
                    }
                    *previous_request = Some((peer_id, now));
                }
            }
        }
        for peer_id in unanswered_by {
            if let Some(peer) = peers.get_mut(&peer_id) {
                peer.request_timed_out();
            }
        }
    }
}

/// This is just named error as it is private to this module.
#[derive(Debug, Clone, thiserror::Error)]
enum Error {
    #[error("unexpected number of pieces: {0}")]
    UnexpectedPiecesLen(usize),
    #[error("chunk index mismatch")]
    ChunkIndexMismatch,
    #[error("chunk out of bounds")]
    ChunkOutOfBounds,
    #[error("invalid group id size")]
    InvalidGroupIdSize,
    // `DecodeError` implements neither `Display` nor `std::error::Error`.
    #[error("SSZ decode error: {0:?}")]
    SszDecodeError(DecodeError),
    #[error("snappy error: {0}")]
    Snappy(snap::Error),
    /// A chunk decompresses to more bytes than the largest valid chunk has.
    #[error("chunk decompresses to {0} bytes, more than the largest valid chunk")]
    DecompressedTooLarge(usize),
    /// A chunk is longer than Snappy compresses its uncompressed length to, at worst.
    #[error("compressed chunk of {0} bytes is longer than its worst case compression")]
    CompressedTooLarge(usize),
}

/// A waggle message about a payload, decoded.
struct Message<E: EthSpec> {
    block_root: Hash256,
    metadata: Option<ChunkMetadata<E>>,
    chunk: Option<Arc<PayloadChunk<E>>>,
}

/// Returns a waggle message about the payload of `block_root` as a peer sends it, carrying its
/// SSZ encoded metadata and a chunk encoded with `encode_chunk`.
#[cfg(test)]
fn object_pieces(
    block_root: Hash256,
    metadata: Option<Bytes>,
    chunk: Option<Bytes>,
) -> ObjectPieces {
    ObjectPieces {
        object_id: Bytes::copy_from_slice(block_root.as_slice()),
        metadata,
        pieces: chunk,
    }
}

/// Encodes `chunk` for a waggle message: snappy compressed SSZ, like gossipsub message data.
fn encode_chunk<E: EthSpec>(chunk: &PayloadChunk<E>) -> Result<Vec<u8>, Error> {
    snap::raw::Encoder::new()
        .compress_vec(&chunk.as_ssz_bytes())
        .map_err(Error::Snappy)
}

/// Decodes a chunk encoded with `encode_chunk`.
fn decode_chunk<E: EthSpec>(data: &[u8]) -> Result<PayloadChunk<E>, Error> {
    // Check the length before decompressing, so that peers can't make us allocate more than the
    // largest chunk takes.
    let len = snap::raw::decompress_len(data).map_err(Error::Snappy)?;
    if len > PayloadChunk::<E>::max_ssz_len() {
        return Err(Error::DecompressedTooLarge(len));
    }
    // Snappy never compresses this badly.
    if data.len() > snap::raw::max_compress_len(len) {
        return Err(Error::CompressedTooLarge(data.len()));
    }
    let ssz_bytes = snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(Error::Snappy)?;
    PayloadChunk::from_ssz_bytes(&ssz_bytes).map_err(Error::SszDecodeError)
}

impl<E: EthSpec> TryFrom<ObjectPieces> for Message<E> {
    type Error = Error;

    fn try_from(value: ObjectPieces) -> Result<Self, Self::Error> {
        Ok(Self {
            block_root: Hash256::new(
                *value
                    .object_id
                    .as_array()
                    .ok_or(Error::InvalidGroupIdSize)?,
            ),
            metadata: value
                .metadata
                .map(|metadata| ChunkMetadata::from_ssz_bytes(&metadata))
                .transpose()
                .map_err(Error::SszDecodeError)?,
            chunk: value
                .pieces
                .map(|chunk| decode_chunk(&chunk))
                .transpose()?
                .map(Arc::new),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_beacon_processor::TestBeaconChainType;
    use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use beacon_processor::{Work, WorkEvent};
    use lighthouse_network::{NetworkConfig, NetworkGlobals};
    use slot_clock::ManualSlotClock;
    use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
    use types::{
        ExecutionPayloadEnvelope, ExecutionPayloadEnvelopeHeze, ExecutionPayloadGloas,
        MainnetEthSpec,
    };

    type E = MainnetEthSpec;

    #[test]
    fn encoded_messages_decode() {
        let block_root = Hash256::repeat_byte(1);
        let mut have = ChunkBitmap::<E>::new();
        have.set(3, true).unwrap();
        let metadata = ChunkMetadata::<E> {
            slot: Slot::new(5),
            have,
            request: ChunkBitmap::<E>::new(),
        };
        let chunk = PayloadChunk::<E> {
            index: 3,
            chunk: VariableList::new(vec![7; 10_000]).unwrap(),
            chunk_inclusion_proof: FixedVector::default(),
        };

        let encoded_chunk = encode_chunk(&chunk).unwrap();
        assert!(encoded_chunk.len() < chunk.as_ssz_bytes().len());

        let message = Message::<E>::try_from(object_pieces(
            block_root,
            Some(metadata.as_ssz_bytes().into()),
            Some(encoded_chunk.into()),
        ))
        .unwrap();
        assert_eq!(message.block_root, block_root);
        assert_eq!(
            message.metadata.unwrap().as_ssz_bytes(),
            metadata.as_ssz_bytes()
        );
        assert_eq!(*message.chunk.unwrap(), chunk);
    }

    /// Returns a payload whose chunks at `valid` are valid.
    fn payload_with_chunks(valid: &[u8]) -> Payload<E> {
        let mut payload = Payload::<E>::new(
            Hash256::repeat_byte(2),
            Hash256::repeat_byte(1),
            Slot::new(5),
        );
        for index in valid {
            payload.chunks[*index as usize] = valid_chunk(*index);
        }
        payload
    }

    fn valid_chunk(index: u8) -> Chunk<E> {
        Chunk::valid(Arc::new(PayloadChunk {
            index,
            chunk: VariableList::new(vec![index; 100]).unwrap(),
            chunk_inclusion_proof: FixedVector::default(),
        }))
    }

    /// Adds a peer we are mutually subscribed with to `peers`, returning its ID and the receiver
    /// of the messages we send it.
    fn add_peer(peers: &mut TopicPeers) -> (PeerId, async_channel::Receiver<ObjectPieces>) {
        let (sender, receiver) = async_channel::unbounded();
        let peer_id = PeerId::random();
        peers.insert(
            peer_id,
            Peer {
                sender: Some(sender),
                subscribed: true,
                ..Peer::new(ConnectionId::new_unchecked(0))
            },
        );
        (peer_id, receiver)
    }

    /// Marks `peer_id` as tracking `payload`, as if it sent metadata announcing `have`.
    fn track(payload: &mut Payload<E>, peer_id: PeerId, have: &[usize]) {
        let payload_peer = payload.peers.entry(peer_id).or_default();
        let has = payload_peer.has.get_or_insert_with(ChunkBitmap::<E>::new);
        for index in have {
            has.set(*index, true).unwrap();
        }
    }

    /// Returns the number of peers the valid chunk at `index` was pushed to.
    fn pushes(payload: &Payload<E>, index: usize) -> usize {
        let Chunk::Valid { pushes, .. } = &payload.chunks[index] else {
            panic!("the chunk should be valid");
        };
        *pushes
    }

    /// Returns the indices of the chunks sent to a peer so far.
    fn pushed_chunks(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<u8> {
        let mut indices = vec![];
        while let Ok(message) = receiver.try_recv() {
            let message = Message::<E>::try_from(message).unwrap();
            indices.push(message.chunk.unwrap().index);
        }
        indices
    }

    fn connection(id: usize) -> ConnectionId {
        ConnectionId::new_unchecked(id)
    }

    #[test]
    fn events_of_a_newer_connection_replace_the_peer() {
        let mut peers = TopicPeers::new();
        let peer_id = PeerId::random();

        // Both subscriptions are established on a connection.
        let (old_sender, old_receiver) = async_channel::unbounded::<ObjectPieces>();
        peer_on_connection(&mut peers, peer_id, connection(1))
            .unwrap()
            .subscribed = true;
        peer_on_connection(&mut peers, peer_id, connection(1))
            .unwrap()
            .sender = Some(old_sender);
        assert!(peers[&peer_id].sender().is_some());

        // The peer subscribes on a newer connection, which starts over and ends the subscription
        // on the previous one.
        let (new_sender, _new_receiver) = async_channel::unbounded::<ObjectPieces>();
        peer_on_connection(&mut peers, peer_id, connection(2))
            .unwrap()
            .sender = Some(new_sender);
        assert!(old_receiver.is_closed());
        assert_eq!(peers[&peer_id].connection_id, connection(2));
        assert!(!peers[&peer_id].subscribed);
        assert!(peers[&peer_id].sender().is_none());

        // The events of the previous connection are stale. Its `Closed` in particular, which can
        // be delivered late, does not remove the peer.
        assert!(peer_on_connection(&mut peers, peer_id, connection(1)).is_none());
        remove_peer_on_connection(&mut peers, peer_id, connection(1));
        assert_eq!(peers[&peer_id].connection_id, connection(2));

        // The `Closed` of the newest connection does.
        remove_peer_on_connection(&mut peers, peer_id, connection(2));
        assert!(peers.is_empty());
    }

    #[test]
    fn peers_are_kept_while_a_subscription_is_alive() {
        let (sender, receiver) = async_channel::unbounded::<ObjectPieces>();
        let mut peer = Peer {
            sender: Some(sender),
            ..Peer::new(connection(1))
        };
        // The peer is subscribed to us, and we may still subscribe to it.
        assert!(peer.keep());
        assert!(peer.sender().is_none());

        // Its subscription ended, and we never subscribed.
        drop(receiver);
        assert!(!peer.keep());

        // We are subscribed to the peer, and it may subscribe to us again.
        peer.subscribed = true;
        assert!(peer.keep());
        assert!(peer.sender().is_none());
    }

    #[test]
    fn valid_chunks_are_encoded_once() {
        let mut payload = payload_with_chunks(&[1]);
        assert!(payload.encoded_chunk(0).is_none());
        assert!(matches!(
            payload.chunks[1],
            Chunk::Valid { encoded: None, .. }
        ));

        let encoded = payload.encoded_chunk(1).unwrap();
        assert_eq!(decode_chunk::<E>(&encoded).unwrap().index, 1);
        // The encoding is kept with the chunk, and returned again.
        let Chunk::Valid {
            encoded: Some(kept),
            ..
        } = &payload.chunks[1]
        else {
            panic!("the chunk should be valid and encoded");
        };
        assert_eq!(*kept, encoded);
        assert_eq!(payload.encoded_chunk(1), Some(encoded));
    }

    #[test]
    fn chunks_are_only_pushed_to_tracking_peers() {
        let mut payload = payload_with_chunks(&[0, 1]);
        let mut peers = TopicPeers::new();
        let (tracking, tracking_receiver) = add_peer(&mut peers);
        let (announced_to, announced_to_receiver) = add_peer(&mut peers);
        let (_, unknown_receiver) = add_peer(&mut peers);
        track(&mut payload, tracking, &[1]);
        // We told this peer about the payload, but it didn't tell us that it tracks it.
        payload.peers.insert(announced_to, PayloadPeer::default());

        payload.push_chunk(0, &peers);
        payload.push_chunk(1, &peers);

        // The tracking peer gets the chunk it lacks, the others nothing.
        assert_eq!(pushed_chunks(&tracking_receiver), vec![0]);
        assert!(pushed_chunks(&announced_to_receiver).is_empty());
        assert!(pushed_chunks(&unknown_receiver).is_empty());
        assert_eq!([pushes(&payload, 0), pushes(&payload, 1)], [1, 0]);

        // Once it tracks the payload, a peer gets the chunks pushed that it missed. No peer gets
        // a chunk twice.
        track(&mut payload, announced_to, &[]);
        payload.push_pending_chunks(&peers);
        assert!(pushed_chunks(&tracking_receiver).is_empty());
        let mut pushed = pushed_chunks(&announced_to_receiver);
        pushed.sort();
        assert_eq!(pushed, vec![0, 1]);
        assert!(pushed_chunks(&unknown_receiver).is_empty());
        assert_eq!([pushes(&payload, 0), pushes(&payload, 1)], [2, 1]);
    }

    #[test]
    fn every_chunk_is_pushed_once_before_any_is_pushed_twice() {
        let chunks = (0..8).collect::<Vec<u8>>();
        let mut payload = payload_with_chunks(&chunks);
        let mut peers = TopicPeers::new();
        let mut receivers = vec![];
        for _ in 0..PUSH_PEERS {
            let (peer_id, receiver) = add_peer(&mut peers);
            track(&mut payload, peer_id, &[]);
            receivers.push(receiver);
        }

        payload.push_chunks(chunks.iter().map(|index| *index as usize).collect(), &peers);

        // Every chunk is pushed to every peer, as there are no more peers than `PUSH_PEERS`.
        let queues = receivers.iter().map(pushed_chunks).collect::<Vec<_>>();
        for queue in &queues {
            let mut sorted = queue.clone();
            sorted.sort();
            assert_eq!(sorted, chunks);
        }

        // The first pushes of the chunks are spread over the peers, so the chunks at the front of
        // the queues are all of them: no chunk waits behind the others in every queue.
        let mut first = queues
            .iter()
            .flat_map(|queue| &queue[..chunks.len() / queues.len()])
            .copied()
            .collect::<Vec<_>>();
        first.sort();
        assert_eq!(first, chunks);
    }

    #[test]
    fn peers_get_at_most_twice_their_share_of_pushes() {
        let chunk_count = E::total_execution_payload_chunks();
        // Few peers can each get every chunk.
        assert!(max_pushes_per_peer::<E>(0) >= chunk_count);
        assert!(max_pushes_per_peer::<E>(3) >= chunk_count);
        assert!(max_pushes_per_peer::<E>(2 * PUSH_PEERS) >= chunk_count);
        // With more peers, each gets twice what an even spread would give it, rounded up.
        assert_eq!(max_pushes_per_peer::<E>(4 * PUSH_PEERS), chunk_count / 2);
        assert_eq!(
            max_pushes_per_peer::<E>(25 * PUSH_PEERS),
            (2 * chunk_count).div_ceil(25)
        );

        // We have every chunk, and our peers start tracking the payload one after the other.
        let chunks = (0..chunk_count as u8).collect::<Vec<_>>();
        let mut payload = payload_with_chunks(&chunks);
        let mut peers = TopicPeers::new();
        let peer_count = 4 * PUSH_PEERS;
        let max_pushes = max_pushes_per_peer::<E>(peer_count);
        let added = (0..peer_count)
            .map(|_| add_peer(&mut peers))
            .collect::<Vec<_>>();
        let pushed = added
            .iter()
            .map(|(peer_id, receiver)| {
                track(&mut payload, *peer_id, &[]);
                payload.push_pending_chunks(&peers);
                pushed_chunks(receiver)
            })
            .collect::<Vec<_>>();

        // The pushes are spread over twice as many peers as each chunk is pushed to, each of
        // which gets its limit, rather than everything going to the first `PUSH_PEERS` peers.
        let (served, unserved) = pushed.split_at(2 * PUSH_PEERS);
        assert!(served.iter().all(|pushed| pushed.len() == max_pushes));
        assert!(unserved.iter().all(|pushed| pushed.is_empty()));
        assert!((0..chunk_count).all(|index| pushes(&payload, index) == PUSH_PEERS));

        // The chunks pushed the least go first, so the first two peers get all of them between
        // them: no chunk is pushed twice before every chunk was pushed once.
        let mut first = pushed[..2].concat();
        first.sort();
        assert_eq!(first, chunks);
    }

    #[test]
    fn chunks_are_pushed_during_the_push_phase_only() {
        let mut payload = payload_with_chunks(&[0, 1, 2]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        track(&mut payload, peer_id, &[]);

        // A payload we publish is pushed whenever: none of its chunks arrived.
        payload.push_chunk(0, &peers);
        assert_eq!(pushed_chunks(&receiver), vec![0]);

        // A payload we receive is pushed for a while after its first chunk arrived.
        let now = Instant::now();
        payload.first_chunk_at = Some(now);
        payload.push_chunk(1, &peers);
        assert_eq!(pushed_chunks(&receiver), vec![1]);

        // Afterwards, its chunks are left for the peers to request.
        payload.first_chunk_at = now.checked_sub(PUSH_PHASE);
        assert!(payload.first_chunk_at.is_some());
        payload.push_chunk(2, &peers);
        payload.push_pending_chunks(&peers);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn metadata_is_sent_along_with_chunks_if_news() {
        let mut payload = payload_with_chunks(&[0, 1]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        track(&mut payload, peer_id, &[]);
        let next_message = || Message::<E>::try_from(receiver.try_recv().unwrap()).unwrap();

        // The peer doesn't know what we have, so the first chunk comes with our metadata.
        payload.push_chunk(0, &peers);
        let message = next_message();
        assert_eq!(message.chunk.unwrap().index, 0);
        let metadata = message.metadata.unwrap();
        assert_eq!(metadata.slot, payload.slot);
        assert_eq!(metadata.have, payload.have());
        assert!(metadata.request.is_zero());

        // Now it knows, so the next chunk comes without, and there is nothing to announce.
        payload.push_chunk(1, &peers);
        let message = next_message();
        assert_eq!(message.chunk.unwrap().index, 1);
        assert!(message.metadata.is_none());
        payload.announce(&peers);
        assert!(receiver.try_recv().is_err());

        // Once we have another chunk, we have news again.
        payload.chunks[2] = valid_chunk(2);
        payload.push_chunk(2, &peers);
        let message = next_message();
        assert_eq!(message.chunk.unwrap().index, 2);
        assert_eq!(message.metadata.unwrap().have, payload.have());
        payload.announce(&peers);
        assert!(receiver.try_recv().is_err());
    }

    /// Returns the chunks requested from a peer so far, in messages that carry no chunk.
    fn requested_chunks(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<usize> {
        let mut indices = vec![];
        while let Ok(message) = receiver.try_recv() {
            let message = Message::<E>::try_from(message).unwrap();
            assert!(message.chunk.is_none());
            let request = message.metadata.unwrap().request;
            indices.extend(
                request
                    .iter()
                    .enumerate()
                    .filter_map(|(index, requested)| requested.then_some(index)),
            );
        }
        indices.sort();
        indices
    }

    #[test]
    fn chunks_are_requested_once_the_request_delay_passed() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        let (peer_id, receiver) = add_peer(&mut peers);
        track(&mut payload, peer_id, &[0]);
        let request_at = payload.registered + REQUEST_DELAY;

        payload.request_missing_chunks(&mut peers, request_at - Duration::from_millis(1));
        assert!(receiver.try_recv().is_err());

        // Announcing does not request, whenever it happens.
        payload.announce(&peers);
        assert_eq!(receiver.len(), 1);
        assert!(requested_chunks(&receiver).is_empty());

        payload.request_missing_chunks(&mut peers, request_at);
        assert_eq!(requested_chunks(&receiver), vec![0]);

        // The requests are outstanding until they time out.
        let timeout_at = request_at + REQUEST_TIMEOUT;
        payload.request_missing_chunks(&mut peers, timeout_at - Duration::from_millis(1));
        assert!(receiver.try_recv().is_err());
        payload.request_missing_chunks(&mut peers, timeout_at);
        assert_eq!(requested_chunks(&receiver), vec![0]);
    }

    #[test]
    fn announcements_are_made_at_intervals() {
        let mut payload = payload_with_chunks(&[0]);
        let now = Instant::now();
        // The first announcement is made right away.
        assert!(payload.announcement_due(now));

        // The next one waits for the interval to pass, so that the chunks that become valid in
        // the meantime are announced together.
        payload.last_announced = Some(now);
        assert!(!payload.announcement_due(now + ANNOUNCE_INTERVAL - Duration::from_millis(1)));
        assert!(payload.announcement_due(now + ANNOUNCE_INTERVAL));

        // That we have every chunk is announced right away, so that peers stop sending us any.
        payload.complete = true;
        assert!(payload.announcement_due(now));
    }

    #[test]
    fn requests_are_spread_over_peers() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        let (peer_a, receiver_a) = add_peer(&mut peers);
        let (peer_b, receiver_b) = add_peer(&mut peers);
        // More chunks than we may request from the peers.
        let chunks = (0..3 * MAX_REQUESTS_PER_PEER).collect::<Vec<_>>();
        track(&mut payload, peer_a, &chunks);
        track(&mut payload, peer_b, &chunks[..MAX_REQUESTS_PER_PEER]);
        let request_at = payload.registered + REQUEST_DELAY;

        payload.request_missing_chunks(&mut peers, request_at);
        let requested_a = requested_chunks(&receiver_a);
        let requested_b = requested_chunks(&receiver_b);
        // Each peer is asked for as many chunks as allowed, and no chunk is requested twice.
        assert_eq!(requested_a.len(), MAX_REQUESTS_PER_PEER);
        assert_eq!(requested_b.len(), MAX_REQUESTS_PER_PEER);
        assert!(requested_a.iter().all(|index| !requested_b.contains(index)));
        assert!(
            requested_b
                .iter()
                .all(|index| *index < MAX_REQUESTS_PER_PEER)
        );

        // No more is requested while these requests are outstanding.
        payload.request_missing_chunks(&mut peers, request_at + Duration::from_millis(1));
        assert!(receiver_a.try_recv().is_err());
        assert!(receiver_b.try_recv().is_err());
    }

    #[test]
    fn timed_out_requests_are_made_to_another_peer() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        let (peer_a, receiver_a) = add_peer(&mut peers);
        let (peer_b, receiver_b) = add_peer(&mut peers);
        track(&mut payload, peer_a, &[0]);
        track(&mut payload, peer_b, &[0]);
        let request_at = payload.registered + REQUEST_DELAY;

        payload.request_missing_chunks(&mut peers, request_at);
        let first_to_a = requested_chunks(&receiver_a) == vec![0];
        assert_ne!(first_to_a, requested_chunks(&receiver_b) == vec![0]);

        // The peer did not send the chunk in time, so the other one is asked.
        payload.request_missing_chunks(&mut peers, request_at + REQUEST_TIMEOUT);
        let (asked_before, asked_now) = if first_to_a {
            (&receiver_a, &receiver_b)
        } else {
            (&receiver_b, &receiver_a)
        };
        assert!(asked_before.try_recv().is_err());
        assert_eq!(requested_chunks(asked_now), vec![0]);
    }

    #[test]
    fn the_request_timeout_grows_with_the_chunks() {
        assert_eq!(request_timeout(0), REQUEST_TIMEOUT);
        assert_eq!(
            request_timeout(1000),
            REQUEST_TIMEOUT + REQUEST_TIMEOUT_PER_BYTE * 1000
        );

        // We don't know how long the chunks of a payload are until we have one.
        let mut payload = payload_with_chunks(&[]);
        assert_eq!(payload.request_timeout(), REQUEST_TIMEOUT);
        payload.chunks[3] = valid_chunk(3);
        assert_eq!(payload.request_timeout(), request_timeout(100));
    }

    #[test]
    fn peers_that_leave_requests_unanswered_are_not_asked() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        // The only peer that has the chunk, so that it is asked again after every timeout.
        let (peer_id, receiver) = add_peer(&mut peers);
        track(&mut payload, peer_id, &[0]);
        let request_at = payload.registered + REQUEST_DELAY;
        let timeout = payload.request_timeout();

        // Every request that timed out counts against the peer.
        for unanswered in 0..=MAX_UNANSWERED_REQUESTS {
            payload.request_missing_chunks(&mut peers, request_at + timeout * unanswered as u32);
            assert_eq!(requested_chunks(&receiver), vec![0]);
            assert_eq!(peers[&peer_id].unanswered_requests, unanswered);
        }

        // At the limit, the peer is not asked anymore.
        let now = request_at + timeout * (MAX_UNANSWERED_REQUESTS as u32 + 1);
        payload.request_missing_chunks(&mut peers, now);
        assert!(receiver.try_recv().is_err());

        // A chunk we lacked makes up for a request, so the peer is asked again.
        peers.get_mut(&peer_id).unwrap().sent_new_chunk();
        assert_eq!(
            peers[&peer_id].unanswered_requests,
            MAX_UNANSWERED_REQUESTS - 1
        );
        payload.request_missing_chunks(&mut peers, now);
        assert_eq!(requested_chunks(&receiver), vec![0]);
    }

    #[test]
    fn peers_that_answered_are_asked_first() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        let (unanswering, unanswering_receiver) = add_peer(&mut peers);
        let (answering, answering_receiver) = add_peer(&mut peers);
        track(&mut payload, unanswering, &[0]);
        track(&mut payload, answering, &[0]);
        peers.get_mut(&unanswering).unwrap().request_timed_out();

        payload.request_missing_chunks(&mut peers, payload.registered + REQUEST_DELAY);
        assert!(unanswering_receiver.try_recv().is_err());
        assert_eq!(requested_chunks(&answering_receiver), vec![0]);
    }

    #[test]
    fn the_service_wakes_up_once_chunks_are_to_be_requested() {
        let mut payload = payload_with_chunks(&[]);
        let mut peers = TopicPeers::new();
        let (peer_id, _receiver) = add_peer(&mut peers);
        let request_at = payload.registered + REQUEST_DELAY;

        // Once the request delay passed.
        assert_eq!(payload.next_wake(payload.registered), Some(request_at));
        // From then on, no chunk becomes requestable unless a peer tells us more.
        assert_eq!(payload.next_wake(request_at), None);

        // Once a request timed out.
        track(&mut payload, peer_id, &[0]);
        payload.request_missing_chunks(&mut peers, request_at);
        let timeout_at = request_at + payload.request_timeout();
        assert_eq!(payload.next_wake(request_at), Some(timeout_at));
        assert_eq!(payload.next_wake(timeout_at), None);

        // And a while after a request could not be queued, as the send queue of the peer was full.
        let (sender, _full_receiver) = async_channel::bounded(1);
        sender
            .try_send(object_pieces(Hash256::repeat_byte(0), None, None))
            .unwrap();
        peers.get_mut(&peer_id).unwrap().sender = Some(sender);
        payload.request_missing_chunks(&mut peers, timeout_at);
        assert_eq!(
            payload.next_wake(timeout_at),
            Some(timeout_at + REQUEST_RETRY_DELAY)
        );

        // Never for a payload we have every chunk of.
        payload.complete = true;
        assert_eq!(payload.next_wake(payload.registered), None);
    }

    #[test]
    fn the_service_wakes_up_once_held_back_news_is_due() {
        let mut payload = payload_with_chunks(&[0]);
        // No chunk is requestable, so there is nothing else to wake up for.
        let now = payload.registered + REQUEST_DELAY;
        assert_eq!(payload.next_wake(now), None);

        // The first news is due right away.
        payload.announcement_pending = true;
        assert_eq!(payload.next_wake(now), None);
        // Later news is held back for the announce interval.
        payload.last_announced = Some(now);
        assert_eq!(payload.next_wake(now), Some(now + ANNOUNCE_INTERVAL));
        assert_eq!(payload.next_wake(now + ANNOUNCE_INTERVAL), None);
        // Without news, there is nothing to announce.
        payload.announcement_pending = false;
        assert_eq!(payload.next_wake(now), None);
    }

    #[test]
    fn pending_pushes_are_made_as_peers_start_tracking() {
        let mut payload = payload_with_chunks(&[0]);
        let mut peers = TopicPeers::new();
        let mut receivers = vec![];

        // Too few peers track the payload when the chunk becomes valid.
        for _ in 0..PUSH_PEERS - 1 {
            let (peer_id, receiver) = add_peer(&mut peers);
            track(&mut payload, peer_id, &[]);
            receivers.push(receiver);
        }
        payload.push_chunk(0, &peers);
        assert_eq!(pushes(&payload, 0), PUSH_PEERS - 1);

        // The remaining push is made once another peer tracks the payload, and no more after.
        for _ in 0..2 {
            let (peer_id, receiver) = add_peer(&mut peers);
            track(&mut payload, peer_id, &[]);
            receivers.push(receiver);
            payload.push_pending_chunks(&peers);
        }
        assert_eq!(pushes(&payload, 0), PUSH_PEERS);
        let pushed = receivers
            .iter()
            .map(|receiver| pushed_chunks(receiver).len())
            .collect::<Vec<_>>();
        assert_eq!(pushed.iter().sum::<usize>(), PUSH_PEERS);
        assert_eq!(pushed.last(), Some(&0));
        assert!(pushed.iter().all(|pushed| *pushed <= 1));
    }

    /// Returns a bitmap with the bits at `indices` set.
    fn bitmap(indices: &[usize]) -> ChunkBitmap<E> {
        let mut bitmap = ChunkBitmap::<E>::new();
        for index in indices {
            bitmap.set(*index, true).unwrap();
        }
        bitmap
    }

    /// Returns metadata of a peer that claims `slot` and has the chunks at `have`.
    fn metadata(slot: Slot, have: &[usize]) -> ChunkMetadata<E> {
        ChunkMetadata {
            slot,
            have: bitmap(have),
            request: ChunkBitmap::<E>::new(),
        }
    }

    #[test]
    fn payloads_are_tracked_until_the_end_of_the_next_slot() {
        let slot_duration = Duration::from_secs(12);
        let disparity = Duration::from_millis(500);
        let slot_clock = ManualSlotClock::new(Slot::new(0), Duration::ZERO, slot_duration);
        let slot = Slot::new(5);
        let slot_start = slot_duration * 5;
        let tracked_at = |time| {
            slot_clock.set_current_time(time);
            tracked_slots(&slot_clock, disparity).unwrap()
        };

        // Not before its slot, allowing for clock disparity.
        assert!(!tracked_at(slot_start - disparity * 2).contains(&slot));
        assert!(tracked_at(slot_start - disparity).contains(&slot));
        // During its slot and the next one.
        assert!(tracked_at(slot_start).contains(&slot));
        assert!(tracked_at(slot_start + slot_duration).contains(&slot));
        assert!(
            tracked_at(slot_start + slot_duration * 2 - Duration::from_millis(1)).contains(&slot)
        );
        // And no longer after, allowing for clock disparity.
        assert!(tracked_at(slot_start + slot_duration * 2 + disparity / 2).contains(&slot));
        assert!(!tracked_at(slot_start + slot_duration * 2 + disparity).contains(&slot));

        // In the first slot, there is no slot before.
        assert_eq!(tracked_at(disparity), Slot::new(0)..=Slot::new(0));
    }

    #[test]
    fn the_tracking_window_moves_on_as_a_slot_starts() {
        let slot_duration = Duration::from_secs(12);
        let disparity = Duration::from_millis(500);
        let slot_clock = ManualSlotClock::new(Slot::new(0), Duration::ZERO, slot_duration);
        let slot_start = slot_duration * 5;
        let wait_at = |time| {
            slot_clock.set_current_time(time);
            time_to_next_tracking_window(&slot_clock, disparity)
        };

        // The window moves on once the slot started, allowing for clock disparity.
        assert_eq!(wait_at(slot_start - disparity), disparity * 2);
        assert_eq!(wait_at(slot_start), disparity);
        assert_eq!(wait_at(slot_start + disparity / 2), disparity / 2);
        // From then on, it stays for a slot.
        assert_eq!(wait_at(slot_start + disparity), slot_duration);
        assert_eq!(wait_at(slot_start + slot_duration), disparity);
    }

    #[test]
    fn peers_announce_a_limited_number_of_unknown_payloads() {
        let mut unknown_payloads = HashMap::<_, UnknownPayload<E>>::new();
        let now = Instant::now();
        let (peer_a, peer_b) = (PeerId::random(), PeerId::random());
        let root = |index: usize| Hash256::repeat_byte(index as u8);
        let slot = Slot::new(5);
        let mut note = |peer_id, block_root, slot, have: &[usize]| {
            note_unknown_payload(
                &mut unknown_payloads,
                peer_id,
                block_root,
                metadata(slot, have),
                now,
            )
        };

        // A peer may announce several payloads, also of the same slot.
        for index in 0..MAX_UNKNOWN_PAYLOADS_PER_PEER {
            assert!(note(peer_a, root(index), slot, &[]));
        }
        // Any more are ignored, whatever their slot.
        assert!(!note(
            peer_a,
            root(MAX_UNKNOWN_PAYLOADS_PER_PEER),
            slot,
            &[]
        ));
        assert!(!note(
            peer_a,
            root(MAX_UNKNOWN_PAYLOADS_PER_PEER),
            slot + 1,
            &[]
        ));
        // Announcing one of them again updates the metadata of the peer.
        assert!(note(peer_a, root(0), slot, &[0, 1]));
        // Other peers may announce the same payloads, also for another slot: we can't tell who is
        // right.
        assert!(note(peer_b, root(0), slot + 1, &[3]));
        assert!(note(peer_b, root(MAX_UNKNOWN_PAYLOADS_PER_PEER), slot, &[]));

        let recorded = |block_root, peer_id| {
            let metadata: &ChunkMetadata<E> = &unknown_payloads[&block_root].peers[&peer_id];
            (metadata.slot, metadata.have.clone())
        };
        assert_eq!(unknown_payloads.len(), MAX_UNKNOWN_PAYLOADS_PER_PEER + 1);
        assert_eq!(unknown_payloads[&root(0)].peers.len(), 2);
        assert_eq!(recorded(root(0), peer_a), (slot, bitmap(&[0, 1])));
        assert_eq!(recorded(root(0), peer_b), (slot + 1, bitmap(&[3])));
        assert!(
            !unknown_payloads[&root(MAX_UNKNOWN_PAYLOADS_PER_PEER)]
                .peers
                .contains_key(&peer_a)
        );

        // Once we track one of them, the peer may announce another.
        unknown_payloads.remove(&root(1));
        assert!(note_unknown_payload(
            &mut unknown_payloads,
            peer_a,
            root(MAX_UNKNOWN_PAYLOADS_PER_PEER),
            metadata(slot, &[]),
            now,
        ));
    }

    /// Returns the unknown payload that `peers` announced, with the slot each claims and what it
    /// has.
    fn unknown_payload(peers: &[(PeerId, Slot, &[usize])]) -> UnknownPayload<E> {
        UnknownPayload {
            peers: peers
                .iter()
                .map(|(peer_id, slot, have)| (*peer_id, metadata(*slot, have)))
                .collect(),
            lookup_at: Instant::now().checked_add(UNKNOWN_PAYLOAD_LOOKUP_DELAY),
        }
    }

    #[test]
    fn peers_that_announced_an_unknown_payload_track_it() {
        let mut payload = payload_with_chunks(&[0, 1]);
        let mut peers = TopicPeers::new();
        let (announcer, announcer_receiver) = add_peer(&mut peers);
        let (other, other_receiver) = add_peer(&mut peers);
        // This peer told us more since we track the payload, which is kept.
        track(&mut payload, other, &[0, 1]);

        let slot = payload.slot;
        payload.adopt_unknown(unknown_payload(&[
            (announcer, slot, &[1]),
            (other, slot, &[0]),
        ]));
        assert_eq!(payload.peers[&announcer].has, Some(bitmap(&[1])));
        assert_eq!(payload.peers[&other].has, Some(bitmap(&[0, 1])));

        // The announcer gets the chunk it lacks, without sending its metadata again.
        payload.push_pending_chunks(&peers);
        assert_eq!(pushed_chunks(&announcer_receiver), vec![0]);
        assert!(pushed_chunks(&other_receiver).is_empty());
    }

    #[test]
    fn a_wrong_slot_claim_only_affects_the_peer_that_made_it() {
        let mut payload = payload_with_chunks(&[0]);
        let mut peers = TopicPeers::new();
        let (liar, liar_receiver) = add_peer(&mut peers);
        let (honest, honest_receiver) = add_peer(&mut peers);

        let slot = payload.slot;
        payload.adopt_unknown(unknown_payload(&[
            (liar, slot + 1, &[]),
            (honest, slot, &[]),
        ]));
        assert!(!payload.peers.contains_key(&liar));

        payload.push_pending_chunks(&peers);
        assert!(pushed_chunks(&liar_receiver).is_empty());
        assert_eq!(pushed_chunks(&honest_receiver), vec![0]);
    }

    #[test]
    fn oversized_chunks_are_not_decompressed() {
        for (len, valid) in [
            (PayloadChunk::<E>::max_ssz_len(), true),
            (PayloadChunk::<E>::max_ssz_len() + 1, false),
        ] {
            let data = snap::raw::Encoder::new()
                .compress_vec(&vec![0; len])
                .unwrap();
            let result = decode_chunk::<E>(&data);
            // Zeroes are no valid `PayloadChunk`, but are only decoded if short enough.
            if valid {
                assert!(matches!(result, Err(Error::SszDecodeError(_))));
            } else {
                assert!(matches!(result, Err(Error::DecompressedTooLarge(_))));
            }
        }
    }

    #[test]
    fn padded_chunks_are_rejected() {
        let chunk = PayloadChunk::<E> {
            index: 0,
            chunk: VariableList::new(vec![7; 100]).unwrap(),
            chunk_inclusion_proof: FixedVector::default(),
        };
        let mut data = encode_chunk(&chunk).unwrap();
        data.resize(
            snap::raw::max_compress_len(chunk.as_ssz_bytes().len()) + 1,
            0,
        );
        assert!(matches!(
            decode_chunk::<E>(&data),
            Err(Error::CompressedTooLarge(_))
        ));
    }

    /// The slot of the payload a `Rig` tracks, which is the current slot.
    const SLOT: Slot = Slot::new(5);

    /// The root of the block whose payload a `Rig` tracks.
    fn block_root() -> Hash256 {
        Hash256::repeat_byte(1)
    }

    /// The root of a block whose payload a `Rig` doesn't track.
    fn unknown_block_root() -> Hash256 {
        Hash256::repeat_byte(9)
    }

    /// What the rigs of the `handle_message` cases share, as it is slow to build: the harness
    /// takes seconds, mostly to load the KZG trusted setup.
    struct RigSetup {
        /// The beacon chain of the services.
        harness: BeaconChainHarness<EphemeralHarnessType<E>>,
        /// The chunks of the payload of `block_root()`, with their inclusion proofs.
        chunks: Vec<Arc<PayloadChunk<E>>>,
        /// The root the chunks are proven against.
        payload_chunks_root: Hash256,
    }

    impl RigSetup {
        fn new() -> Self {
            let harness = BeaconChainHarness::builder(E::default())
                .default_spec()
                // Fewer validators than slots in an epoch don't make a genesis state from Gloas.
                .deterministic_keypairs(E::slots_per_epoch() as usize)
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();

            // The transaction bytes vary, so that no two chunks are equal.
            let transaction =
                ProgressiveVariableList::new((0..10_000).map(|i| (i % 251) as u8).collect())
                    .unwrap();
            let envelope = ExecutionPayloadEnvelope::<E>::Heze(ExecutionPayloadEnvelopeHeze {
                payload: ExecutionPayloadGloas {
                    transactions: ProgressiveVariableList::new(vec![transaction]).unwrap(),
                    ..Default::default()
                },
                ..Default::default()
            });
            let (chunks, payload_chunks_root) =
                PayloadChunk::build_payload_chunks(&envelope).unwrap();

            RigSetup {
                harness,
                chunks: chunks.into_iter().map(Arc::new).collect(),
                payload_chunks_root,
            }
        }

        /// Returns a new service, which shares nothing but the beacon chain with the others.
        fn rig(&self) -> Rig {
            let network_globals = NetworkGlobals::new_test_globals(
                vec![],
                Arc::new(NetworkConfig::default()),
                self.harness.spec.clone(),
            );
            let (network_beacon_processor, beacon_processor_rx, network_rx) =
                NetworkBeaconProcessor::null_for_testing_with_network_receiver(
                    Arc::new(network_globals),
                    mpsc::unbounded_channel().0,
                    self.harness.chain.clone(),
                    self.harness.runtime.task_executor.clone(),
                );

            // A clock of its own, at the start of `SLOT`, so that a case can let time pass.
            let slot_duration = self.harness.chain.slot_clock.slot_duration();
            let slot_clock = ManualSlotClock::new(Slot::new(0), Duration::ZERO, slot_duration);
            slot_clock.set_slot(SLOT.as_u64());

            let payload = Payload::new(self.payload_chunks_root, block_root(), SLOT);
            // The service is not run, so nothing is sent on these channels.
            let service = PayloadDisseminationService {
                fork_digest: [0; 4],
                message_recv: mpsc::channel(1).1,
                topic_events: async_channel::unbounded().1,
                unsubscribe: oneshot::channel().1,
                slot_clock,
                network_beacon_processor: Arc::new(network_beacon_processor),
                next_clean_up: Instant::now(),
                requests_pending: false,
                peers: TopicPeers::new(),
                payloads: HashMap::from([(block_root(), payload)]),
                unknown_payloads: HashMap::new(),
                previous_payloads: Vec::new(),
            };

            Rig {
                service,
                chunks: self.chunks.clone(),
                network_rx,
                beacon_processor_rx,
            }
        }
    }

    /// A dissemination service that tracks the payload of `block_root()`, none of whose chunks it
    /// has, to pass the messages of peers to.
    struct Rig {
        service: PayloadDisseminationService<TestBeaconChainType<E>>,
        /// The chunks of the tracked payload, with their inclusion proofs.
        chunks: Vec<Arc<PayloadChunk<E>>>,
        /// Receives what the service sends to the network service: its reports of peers.
        network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
        /// Receives what the service sends to the beacon processor: the payloads it reassembled.
        beacon_processor_rx: mpsc::Receiver<WorkEvent<E>>,
    }

    impl Rig {
        /// The tracked payload.
        fn payload(&mut self) -> &mut Payload<E> {
            self.service.payloads.get_mut(&block_root()).unwrap()
        }

        /// Adds a peer we are mutually subscribed with, see `add_peer`.
        fn add_peer(&mut self) -> (PeerId, async_channel::Receiver<ObjectPieces>) {
            add_peer(&mut self.service.peers)
        }

        /// Makes us hold the chunk at `index` of the tracked payload, pushed to no peer yet.
        fn hold_chunk(&mut self, index: usize) {
            let chunk = self.chunks[index].clone();
            self.payload().chunks[index] = Chunk::valid(chunk);
        }

        /// Whether we hold the chunk at `index` of the tracked payload.
        fn holds_chunk(&mut self, index: usize) -> bool {
            matches!(self.payload().chunks[index], Chunk::Valid { .. })
        }

        /// Returns the chunk at `index` of the tracked payload with other content, which its
        /// inclusion proof doesn't fit.
        fn altered_chunk(&self, index: usize) -> Arc<PayloadChunk<E>> {
            let mut chunk = (*self.chunks[index]).clone();
            let len = chunk.chunk.len();
            chunk.chunk = VariableList::new(vec![0xff; len]).unwrap();
            Arc::new(chunk)
        }

        /// Passes a message of `peer_id` about the tracked payload to the service.
        async fn receive(
            &mut self,
            peer_id: PeerId,
            metadata: Option<ChunkMetadata<E>>,
            chunk: Option<Arc<PayloadChunk<E>>>,
        ) {
            self.receive_about(block_root(), peer_id, metadata, chunk)
                .await;
        }

        /// Passes a message of `peer_id` about the payload of `block_root` to the service.
        async fn receive_about(
            &mut self,
            block_root: Hash256,
            peer_id: PeerId,
            metadata: Option<ChunkMetadata<E>>,
            chunk: Option<Arc<PayloadChunk<E>>>,
        ) {
            let message = Message {
                block_root,
                metadata,
                chunk,
            };
            self.service.handle_message(peer_id, message).await.unwrap();
        }

        /// Sets the clock of the service to the start of `slot`, plus the clock disparity that
        /// tracking windows allow for, and does the clean up that the service does periodically.
        fn clean_up_in_slot(&mut self, slot: Slot) {
            let slot_clock = &self.service.slot_clock;
            let disparity = self
                .service
                .network_beacon_processor
                .chain
                .spec
                .maximum_gossip_clock_disparity();
            slot_clock
                .set_current_time(slot_clock.slot_duration() * slot.as_u64() as u32 + disparity);
            self.service.clean_up();
        }

        /// Returns the peers the service reported since the last call, with the reasons.
        fn reports(&mut self) -> Vec<(PeerId, &'static str)> {
            let mut reports = vec![];
            while let Ok(message) = self.network_rx.try_recv() {
                let NetworkMessage::ReportPeer { peer_id, msg, .. } = message else {
                    panic!("the service should only report peers");
                };
                reports.push((peer_id, msg));
            }
            reports
        }
    }

    /// Returns the messages sent to a peer so far.
    fn sent(receiver: &async_channel::Receiver<ObjectPieces>) -> Vec<Message<E>> {
        let mut messages = vec![];
        while let Ok(message) = receiver.try_recv() {
            messages.push(Message::<E>::try_from(message).unwrap());
        }
        messages
    }

    /// Returns metadata of a peer that has the chunks at `have` of the payload a `Rig` tracks,
    /// and requests the ones at `request`.
    fn request(have: &[usize], request: &[usize]) -> ChunkMetadata<E> {
        ChunkMetadata {
            request: bitmap(request),
            ..metadata(SLOT, have)
        }
    }

    /// Runs the cases below, each on a service of its own.
    ///
    /// They are one test to share a `RigSetup`: nextest runs every test in a process of its own,
    /// so separate tests would each build one.
    #[tokio::test]
    async fn handle_message() {
        let setup = RigSetup::new();
        valid_chunks_are_kept_and_pushed_on(setup.rig()).await;
        invalid_chunks_are_rejected_and_their_sender_ignored(setup.rig()).await;
        a_chunk_sent_twice_is_penalized(setup.rig()).await;
        a_chunk_with_an_index_out_of_bounds_is_penalized(setup.rig()).await;
        the_payload_is_handed_over_once_every_chunk_is_valid(setup.rig()).await;
        metadata_claiming_another_slot_is_penalized(setup.rig()).await;
        a_peer_that_lost_a_chunk_is_penalized(setup.rig()).await;
        requested_chunks_are_served_once(setup.rig()).await;
        requests_for_held_chunks_are_penalized(setup.rig()).await;
        metadata_is_answered_at_once_unless_it_came_with_a_chunk(setup.rig()).await;
        chunks_of_untracked_payloads_are_penalized(setup.rig()).await;
        chunks_of_payloads_tracked_until_recently_are_not_penalized(setup.rig()).await;
        announcements_of_unknown_payloads_are_remembered_in_their_tracking_window(setup.rig())
            .await;
    }

    async fn valid_chunks_are_kept_and_pushed_on(mut rig: Rig) {
        let (sender, sender_receiver) = rig.add_peer();
        let (tracker, tracker_receiver) = rig.add_peer();
        track(rig.payload(), tracker, &[]);

        let chunk = rig.chunks[3].clone();
        rig.receive(sender, None, Some(chunk.clone())).await;

        // The chunk is kept, and pushed to the peer that tracks the payload.
        assert!(rig.holds_chunk(3));
        assert_eq!(pushed_chunks(&tracker_receiver), vec![3]);
        // Its sender is not told that we have it right away, but with the next announcements.
        assert!(sent(&sender_receiver).is_empty());
        assert!(rig.payload().announcement_pending);
        assert!(rig.reports().is_empty());

        // Another peer may send the chunk as well, which changes nothing.
        rig.receive(PeerId::random(), None, Some(chunk)).await;
        assert!(pushed_chunks(&tracker_receiver).is_empty());
        assert_eq!(pushes(rig.payload(), 3), 1);
        assert!(rig.reports().is_empty());
    }

    async fn invalid_chunks_are_rejected_and_their_sender_ignored(mut rig: Rig) {
        let (tracker, tracker_receiver) = rig.add_peer();
        track(rig.payload(), tracker, &[]);

        // The inclusion proof doesn't fit the chunk.
        let peer_id = PeerId::random();
        rig.receive(peer_id, None, Some(rig.altered_chunk(3))).await;
        assert!(!rig.holds_chunk(3));
        assert!(pushed_chunks(&tracker_receiver).is_empty());
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_invalid_chunk")]);

        // The peer is ignored for the rest of the payload, also if it sends a valid chunk.
        rig.receive(peer_id, None, Some(rig.chunks[4].clone()))
            .await;
        assert!(!rig.holds_chunk(4));
        assert!(rig.reports().is_empty());

        // A chunk that differs from the one we hold is invalid too.
        rig.hold_chunk(5);
        let peer_id = PeerId::random();
        rig.receive(peer_id, None, Some(rig.altered_chunk(5))).await;
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_invalid_chunk")]);
    }

    async fn a_chunk_sent_twice_is_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();
        let chunk = rig.chunks[3].clone();

        rig.receive(peer_id, None, Some(chunk.clone())).await;
        assert!(rig.reports().is_empty());

        rig.receive(peer_id, None, Some(chunk)).await;
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_duplicate_chunk")]);
    }

    async fn a_chunk_with_an_index_out_of_bounds_is_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();
        let mut chunk = (*rig.chunks[3]).clone();
        chunk.index = E::total_execution_payload_chunks() as u8;

        rig.receive(peer_id, None, Some(Arc::new(chunk))).await;

        let reports = rig.reports();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, peer_id);
    }

    async fn the_payload_is_handed_over_once_every_chunk_is_valid(mut rig: Rig) {
        let peer_id = PeerId::random();
        let (last_chunk, other_chunks) = rig.chunks.split_last().unwrap();
        let (last_chunk, other_chunks) = (last_chunk.clone(), other_chunks.to_vec());

        for chunk in other_chunks {
            rig.receive(peer_id, None, Some(chunk)).await;
        }
        assert!(!rig.payload().complete);
        assert!(rig.beacon_processor_rx.try_recv().is_err());

        // The last chunk completes the payload, which is handed to the beacon processor.
        rig.receive(peer_id, None, Some(last_chunk.clone())).await;
        assert!(rig.payload().complete);
        let event = rig.beacon_processor_rx.try_recv().unwrap();
        assert!(matches!(event.work, Work::GossipExecutionPayload(_)));

        // It is handed over once, also if peers keep sending its chunks.
        rig.receive(PeerId::random(), None, Some(last_chunk)).await;
        assert!(rig.beacon_processor_rx.try_recv().is_err());
        assert!(rig.reports().is_empty());
    }

    async fn metadata_claiming_another_slot_is_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();

        rig.receive(peer_id, Some(metadata(SLOT + 1, &[1])), None)
            .await;

        assert_eq!(rig.reports(), vec![(peer_id, "waggle_wrong_slot")]);
        // The peer doesn't count as tracking the payload.
        assert!(rig.payload().peers[&peer_id].has.is_none());
    }

    async fn a_peer_that_lost_a_chunk_is_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();

        // A peer has more chunks over time.
        rig.receive(peer_id, Some(metadata(SLOT, &[1])), None).await;
        rig.receive(peer_id, Some(metadata(SLOT, &[1, 2])), None)
            .await;
        assert!(rig.reports().is_empty());

        // It never has fewer.
        rig.receive(peer_id, Some(metadata(SLOT, &[2])), None).await;
        assert_eq!(rig.reports(), vec![(peer_id, "waggle_lost_chunk")]);
    }

    async fn requested_chunks_are_served_once(mut rig: Rig) {
        rig.hold_chunk(1);
        rig.hold_chunk(2);
        let (peer_id, receiver) = rig.add_peer();
        track(rig.payload(), peer_id, &[]);

        // The peer requests a chunk we have, and one we lack.
        rig.receive(peer_id, Some(request(&[], &[1, 5])), None)
            .await;

        // We send the one we have, along with what we have, as the peer doesn't know yet.
        let messages = sent(&receiver);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].chunk.as_ref().unwrap().index, 1);
        assert_eq!(messages[0].metadata.as_ref().unwrap().have, bitmap(&[1, 2]));
        // A chunk served on request is no push.
        assert_eq!(pushes(rig.payload(), 1), 0);
        assert_eq!(rig.payload().peers[&peer_id].pushes, 0);

        // The chunk is not sent to the peer again.
        rig.receive(peer_id, Some(request(&[], &[1])), None).await;
        assert!(sent(&receiver).is_empty());
        assert!(rig.reports().is_empty());
    }

    async fn requests_for_held_chunks_are_penalized(mut rig: Rig) {
        rig.hold_chunk(1);

        // The peer requests a chunk it claims to have.
        let (peer_id, receiver) = rig.add_peer();
        rig.receive(peer_id, Some(request(&[1], &[1])), None).await;
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_request_for_held_chunk")]
        );
        assert!(sent(&receiver).is_empty());

        // The peer requests a chunk it sent us.
        let (peer_id, receiver) = rig.add_peer();
        rig.receive(peer_id, None, Some(rig.chunks[3].clone()))
            .await;
        rig.receive(peer_id, Some(request(&[], &[3])), None).await;
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_request_for_held_chunk")]
        );
        assert!(sent(&receiver).is_empty());
    }

    async fn metadata_is_answered_at_once_unless_it_came_with_a_chunk(mut rig: Rig) {
        rig.hold_chunk(1);
        let (peer_id, receiver) = rig.add_peer();

        // The first metadata of a peer tells us that it tracks the payload. We tell it what we
        // have, and push it the chunk we didn't push to enough peers yet.
        rig.receive(peer_id, Some(metadata(SLOT, &[])), None).await;
        let messages = sent(&receiver);
        assert_eq!(messages.len(), 2);
        assert!(messages[0].chunk.is_none());
        assert_eq!(messages[0].metadata.as_ref().unwrap().have, bitmap(&[1]));
        assert_eq!(messages[1].chunk.as_ref().unwrap().index, 1);
        assert!(messages[1].metadata.is_none());
        assert_eq!(pushes(rig.payload(), 1), 1);

        // The peer pushes a chunk, with its metadata. We don't answer every such message, but
        // announce what we have once the burst is over.
        let chunk = rig.chunks[2].clone();
        rig.receive(peer_id, Some(metadata(SLOT, &[1, 2])), Some(chunk))
            .await;
        assert!(rig.holds_chunk(2));
        assert!(sent(&receiver).is_empty());
        assert!(rig.payload().announcement_pending);

        // Metadata without a chunk is answered at once, if we have news for the peer.
        rig.receive(peer_id, Some(metadata(SLOT, &[1, 2])), None)
            .await;
        let messages = sent(&receiver);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].chunk.is_none());
        assert_eq!(messages[0].metadata.as_ref().unwrap().have, bitmap(&[1, 2]));
        assert!(rig.reports().is_empty());
    }

    async fn chunks_of_untracked_payloads_are_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();
        let chunk = rig.chunks[3].clone();

        rig.receive_about(unknown_block_root(), peer_id, None, Some(chunk.clone()))
            .await;
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_chunk_of_untracked_payload")]
        );

        // Metadata that comes with such a chunk is not remembered.
        rig.receive_about(
            unknown_block_root(),
            peer_id,
            Some(metadata(SLOT, &[3])),
            Some(chunk),
        )
        .await;
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_chunk_of_untracked_payload")]
        );
        assert!(rig.service.unknown_payloads.is_empty());
    }

    async fn chunks_of_payloads_tracked_until_recently_are_not_penalized(mut rig: Rig) {
        let peer_id = PeerId::random();

        // The payload is tracked during its slot and the next one.
        rig.clean_up_in_slot(SLOT + TRACKED_SLOTS_AFTER_OWN);
        assert!(rig.service.payloads.contains_key(&block_root()));
        rig.clean_up_in_slot(SLOT + TRACKED_SLOTS_AFTER_OWN + 1);
        assert!(rig.service.payloads.is_empty());

        // A peer may have sent a chunk before, which arrives now. It is dropped, as is any chunk
        // of an untracked payload, but the peer is not penalized.
        rig.receive(peer_id, None, Some(rig.chunks[3].clone()))
            .await;
        assert!(rig.service.payloads.is_empty());
        assert!(rig.reports().is_empty());

        // Another slot later, the chunk can no longer have been sent in time.
        rig.clean_up_in_slot(SLOT + TRACKED_SLOTS_AFTER_OWN + 1 + PREVIOUS_PAYLOAD_SLOTS);
        assert!(rig.service.previous_payloads.is_empty());
        rig.receive(peer_id, None, Some(rig.chunks[4].clone()))
            .await;
        assert_eq!(
            rig.reports(),
            vec![(peer_id, "waggle_chunk_of_untracked_payload")]
        );
    }

    async fn announcements_of_unknown_payloads_are_remembered_in_their_tracking_window(
        mut rig: Rig,
    ) {
        let peer_id = PeerId::random();

        // Payloads of slots outside the tracking window are not remembered. Peers may announce
        // them, as their clocks differ from ours.
        for slot in [SLOT - 3, SLOT + 1] {
            rig.receive_about(
                unknown_block_root(),
                peer_id,
                Some(metadata(slot, &[1])),
                None,
            )
            .await;
            assert!(rig.service.unknown_payloads.is_empty());
        }

        // Payloads of the current and the previous slot are, with what the peer has.
        for slot in [SLOT - 1, SLOT] {
            rig.receive_about(
                unknown_block_root(),
                peer_id,
                Some(metadata(slot, &[1])),
                None,
            )
            .await;
            let unknown_payload = &rig.service.unknown_payloads[&unknown_block_root()];
            assert_eq!(unknown_payload.peers[&peer_id].slot, slot);
            assert_eq!(unknown_payload.peers[&peer_id].have, bitmap(&[1]));
        }

        // A peer only makes us remember a few unknown payloads. What it announces beyond that is
        // ignored.
        for byte in 0..MAX_UNKNOWN_PAYLOADS_PER_PEER as u8 {
            rig.receive_about(
                Hash256::repeat_byte(100 + byte),
                peer_id,
                Some(metadata(SLOT, &[1])),
                None,
            )
            .await;
        }
        assert_eq!(
            rig.service.unknown_payloads.len(),
            MAX_UNKNOWN_PAYLOADS_PER_PEER
        );

        // Nothing is tracked or requested yet, and nobody is penalized.
        assert_eq!(rig.service.payloads.len(), 1);
        assert!(rig.reports().is_empty());
    }
}

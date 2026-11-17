//! The channels to the payload dissemination services, and the lifecycle of the services.
//!
//! There is one `PayloadDisseminationService` per payload topic, i.e. per fork digest. The channel
//! to each of them is created at startup, for the current and every scheduled fork digest, so the
//! senders never change and are shared without a lock. Payloads are thereby registered with the
//! service of their topic directly, without going through the network service.
//!
//! The network service only does what requires the swarm: it subscribes to the topics, and learns
//! which peers subscribed to them. It tells `PayloadDisseminationServices` about both, which runs
//! the service of a topic for as long as we are subscribed to it.

use super::payload::{
    ForkDigest, NewPayload, PayloadDisseminationMessage, PayloadDisseminationService,
};
use crate::NetworkBeaconProcessor;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::PeerId;
use lighthouse_network::libp2p::swarm::ConnectionId;
use lighthouse_network::types::WaggleKind;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::oneshot;
use tracing::{debug, warn};
use types::{Epoch, EthSpec, ForkContext, Hash256, SignedBeaconBlock};
use waggle::handler::{PieceSender, TopicEvent};

/// The size of the message queue of each payload dissemination service: the payloads to track, of
/// which there are few per slot, and the peers that subscribed to its topic.
const MESSAGE_QUEUE_SIZE: usize = 1_024;

type MessageSender<E> = mpsc::Sender<PayloadDisseminationMessage<E>>;
type MessageReceiver<E> = mpsc::Receiver<PayloadDisseminationMessage<E>>;

/// Why a message did not reach a payload dissemination service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDisseminationError {
    /// There is no topic for the fork digest: it is of a fork before Heze, or of one that was
    /// already over when we started.
    NoTopic,
    /// The service of the topic ended, as we unsubscribed from the topic.
    Unsubscribed,
    /// The message queue of the service is full.
    QueueFull,
}

/// The senders to the payload dissemination services, of which there is one per topic, i.e. per
/// fork digest.
#[derive(Clone)]
pub struct PayloadDisseminationSenders<E: EthSpec> {
    /// The fork digest of each topic and the sender to its service, by the epoch the fork digest
    /// applies from.
    topics: Arc<BTreeMap<Epoch, (ForkDigest, MessageSender<E>)>>,
}

/// The receiving ends of `PayloadDisseminationSenders`, by the fork digest of their topic. Each is
/// handed to the service of its topic once we subscribe to it.
pub struct PayloadDisseminationReceivers<E: EthSpec> {
    receivers: HashMap<ForkDigest, MessageReceiver<E>>,
}

impl<E: EthSpec> PayloadDisseminationSenders<E> {
    /// Creates the channels to the services of the payload topics of the current and the scheduled
    /// fork digests. These are all the topics we will ever subscribe to, as we never subscribe to
    /// the topics of forks that are over.
    pub fn new(fork_context: &ForkContext) -> (Self, PayloadDisseminationReceivers<E>) {
        let spec = &fork_context.spec;
        let current_fork_epoch = fork_context.current_fork_epoch();

        let mut topics = BTreeMap::new();
        let mut receivers = HashMap::new();
        for epoch in spec.all_digest_epochs() {
            if epoch < current_fork_epoch
                || !WaggleKind::ExecutionPayload.exists_at(spec.fork_name_at_epoch(epoch))
            {
                continue;
            }
            let fork_digest = fork_context.context_bytes(epoch);
            let (sender, receiver) = mpsc::channel(MESSAGE_QUEUE_SIZE);
            topics.insert(epoch, (fork_digest, sender));
            receivers.insert(fork_digest, receiver);
        }

        (
            Self {
                topics: Arc::new(topics),
            },
            PayloadDisseminationReceivers { receivers },
        )
    }

    /// Returns senders without any topic, which drop every message.
    pub fn disabled() -> Self {
        Self {
            topics: Arc::new(BTreeMap::new()),
        }
    }

    /// Registers `payload` with the service of the topic it is disseminated on, which is the one
    /// of the fork digest at its slot.
    pub fn new_payload(&self, payload: NewPayload<E>) -> Result<(), PayloadDisseminationError> {
        let epoch = payload.slot.epoch(E::slots_per_epoch());
        // The topics of the fork digests before the first one are missing, so this finds no topic
        // for their epochs, rather than the one of another fork digest.
        let (_, sender) = self
            .topics
            .range(..=epoch)
            .next_back()
            .map(|(_, topic)| topic)
            .ok_or(PayloadDisseminationError::NoTopic)?;
        try_send(sender, PayloadDisseminationMessage::NewPayload(payload))
    }

    /// Registers the payload `block` commits to, if its bid commits to payload chunks, see
    /// `new_payload`.
    ///
    /// The block is that of a past fork if we looked it up, and its payload is ignored then. So
    /// errors are not returned, as there is nothing for the caller to do about them.
    pub fn new_payload_of_block(&self, block_root: Hash256, block: &SignedBeaconBlock<E>) {
        if let Some(payload) = NewPayload::of_block(block_root, block)
            && let Err(error) = self.new_payload(payload)
        {
            debug!(
                ?error,
                %block_root,
                slot = %block.slot(),
                "Payload not registered for dissemination"
            );
        }
    }

    /// Sends `message` to the service of the topic of `fork_digest`.
    fn send(
        &self,
        fork_digest: ForkDigest,
        message: PayloadDisseminationMessage<E>,
    ) -> Result<(), PayloadDisseminationError> {
        let (_, sender) = self
            .topics
            .values()
            .find(|(topic_fork_digest, _)| *topic_fork_digest == fork_digest)
            .ok_or(PayloadDisseminationError::NoTopic)?;
        try_send(sender, message)
    }
}

fn try_send<E: EthSpec>(
    sender: &MessageSender<E>,
    message: PayloadDisseminationMessage<E>,
) -> Result<(), PayloadDisseminationError> {
    sender.try_send(message).map_err(|error| match error {
        TrySendError::Closed(_) => PayloadDisseminationError::Unsubscribed,
        TrySendError::Full(_) => {
            warn!("Payload dissemination queue is full");
            PayloadDisseminationError::QueueFull
        }
    })
}

/// A topic we did not subscribe to yet, so its service is not running.
struct PendingTopic<E: EthSpec> {
    /// Handed to the service once it starts.
    message_recv: MessageReceiver<E>,
    /// The peers that subscribed to the topic already, which they may do before us ahead of a
    /// fork, each with the connection it subscribed on.
    ///
    /// Kept here rather than queued for the service, as nothing drains its queue yet: a peer
    /// could fill it by subscribing over and over, and we would miss the peers subscribing after.
    peers: HashMap<PeerId, (ConnectionId, PieceSender)>,
}

/// Runs the `PayloadDisseminationService` of each payload topic for as long as we are subscribed
/// to the topic.
///
/// Owned by the network service, which tells us when it subscribed to a topic, when a peer did,
/// and which topics to unsubscribe from.
pub struct PayloadDisseminationServices<T: BeaconChainTypes> {
    senders: PayloadDisseminationSenders<T::EthSpec>,
    /// The topics we did not subscribe to yet, by fork digest.
    pending: HashMap<ForkDigest, PendingTopic<T::EthSpec>>,
    /// The topics we are subscribed to, by fork digest. Dropping the sender of a topic ends its
    /// service, which unsubscribes from the topic.
    ///
    /// This is not a message to the service, as a full queue must not keep us subscribed.
    subscribed: HashMap<ForkDigest, oneshot::Sender<()>>,
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
}

impl<T: BeaconChainTypes> PayloadDisseminationServices<T> {
    pub fn new(
        senders: PayloadDisseminationSenders<T::EthSpec>,
        receivers: PayloadDisseminationReceivers<T::EthSpec>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    ) -> Self {
        let pending = receivers
            .receivers
            .into_iter()
            .map(|(fork_digest, message_recv)| {
                let topic = PendingTopic {
                    message_recv,
                    peers: HashMap::new(),
                };
                (fork_digest, topic)
            })
            .collect();
        Self {
            senders,
            pending,
            subscribed: HashMap::new(),
            network_beacon_processor,
        }
    }

    /// Starts the service of the topic of `fork_digest`, which we subscribed to. The events of the
    /// topic arrive on `topic_events`, and dropping it unsubscribes.
    pub fn subscribed(
        &mut self,
        fork_digest: ForkDigest,
        topic_events: async_channel::Receiver<TopicEvent>,
    ) {
        let Some(topic) = self.pending.remove(&fork_digest) else {
            // We unsubscribe again by dropping `topic_events`.
            warn!(
                fork_digest = hex::encode(fork_digest),
                "No payload dissemination service to start for topic"
            );
            return;
        };
        let (unsubscribe_send, unsubscribe_recv) = oneshot::channel();
        PayloadDisseminationService::spawn(
            fork_digest,
            topic.message_recv,
            topic_events,
            unsubscribe_recv,
            topic.peers,
            self.network_beacon_processor.clone(),
        );
        self.subscribed.insert(fork_digest, unsubscribe_send);
    }

    /// Records that `peer_id` subscribed to the topic of `fork_digest` on the connection
    /// `connection_id`. Pieces queued on `sender` are sent to the peer.
    pub fn peer_subscribed(
        &mut self,
        fork_digest: ForkDigest,
        peer_id: PeerId,
        connection_id: ConnectionId,
        sender: PieceSender,
    ) {
        if let Some(topic) = self.pending.get_mut(&fork_digest) {
            // Forget the peers whose subscription ended since, so that we remember no more peers
            // than are connected.
            topic.peers.retain(|_, (_, sender)| !sender.is_closed());
            // Keep the subscription on the newest connection of the peer, like the service does.
            if topic
                .peers
                .get(&peer_id)
                .is_none_or(|(known, _)| *known <= connection_id)
            {
                topic.peers.insert(peer_id, (connection_id, sender));
            }
            return;
        }
        // Peers may subscribe to topics we have none for, or unsubscribed from. Dropping `sender`
        // ends their subscription.
        if let Err(error) = self.senders.send(
            fork_digest,
            PayloadDisseminationMessage::PeerSubscribed {
                peer_id,
                connection_id,
                sender,
            },
        ) {
            debug!(
                ?error,
                %peer_id,
                fork_digest = hex::encode(fork_digest),
                "Ignoring subscription to payload topic"
            );
        }
    }

    /// Unsubscribes from the topics whose fork digest is not in `fork_digests`, by ending their
    /// services.
    pub fn unsubscribe_except(&mut self, fork_digests: &[ForkDigest]) {
        self.subscribed
            .retain(|fork_digest, _| fork_digests.contains(fork_digest));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{BlobParameters, BlobSchedule, ForkName, MainnetEthSpec, Slot};

    type E = MainnetEthSpec;

    /// The epoch Heze starts at, and with it the first fork digest with a payload topic.
    const HEZE_EPOCH: u64 = 10;
    /// The epoch the blob parameters change at, and with them the fork digest.
    const BPO_EPOCH: u64 = 20;

    /// Returns the fork context of a chain at `current_epoch`, with Gloas from genesis.
    fn fork_context(current_epoch: u64) -> ForkContext {
        let mut spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
        spec.heze_fork_epoch = Some(Epoch::new(HEZE_EPOCH));
        spec.blob_schedule = BlobSchedule::new(vec![BlobParameters {
            epoch: Epoch::new(BPO_EPOCH),
            max_blobs_per_block: 12,
        }]);
        ForkContext::new::<E>(slot(current_epoch), Hash256::repeat_byte(1), &spec)
    }

    fn slot(epoch: u64) -> Slot {
        Epoch::new(epoch).start_slot(E::slots_per_epoch())
    }

    fn payload(epoch: u64) -> NewPayload<E> {
        NewPayload {
            payload_chunks_root: Hash256::repeat_byte(2),
            block_root: Hash256::repeat_byte(3),
            slot: slot(epoch),
            chunks: None,
        }
    }

    /// Returns the slots of the payloads queued for the service of the topic of `fork_digest`.
    fn queued_payloads(
        receivers: &mut PayloadDisseminationReceivers<E>,
        fork_digest: ForkDigest,
    ) -> Vec<Slot> {
        let receiver = receivers.receivers.get_mut(&fork_digest).unwrap();
        let mut slots = vec![];
        while let Ok(message) = receiver.try_recv() {
            match message {
                PayloadDisseminationMessage::NewPayload(payload) => slots.push(payload.slot),
                PayloadDisseminationMessage::PeerSubscribed { .. } => {
                    panic!("unexpected peer subscription")
                }
            }
        }
        slots
    }

    #[test]
    fn payloads_are_routed_by_the_fork_digest_at_their_slot() {
        let fork_context = fork_context(0);
        let heze_fork_digest = fork_context.context_bytes(Epoch::new(HEZE_EPOCH));
        let bpo_fork_digest = fork_context.context_bytes(Epoch::new(BPO_EPOCH));
        assert_ne!(heze_fork_digest, bpo_fork_digest);
        let (senders, mut receivers) = PayloadDisseminationSenders::<E>::new(&fork_context);

        // Gloas has no payload topic.
        assert_eq!(receivers.receivers.len(), 2);
        assert_eq!(
            senders.new_payload(payload(HEZE_EPOCH - 1)),
            Err(PayloadDisseminationError::NoTopic)
        );

        for epoch in [HEZE_EPOCH, BPO_EPOCH - 1, BPO_EPOCH, BPO_EPOCH + 5] {
            assert_eq!(senders.new_payload(payload(epoch)), Ok(()));
        }
        assert_eq!(
            queued_payloads(&mut receivers, heze_fork_digest),
            vec![slot(HEZE_EPOCH), slot(BPO_EPOCH - 1)]
        );
        assert_eq!(
            queued_payloads(&mut receivers, bpo_fork_digest),
            vec![slot(BPO_EPOCH), slot(BPO_EPOCH + 5)]
        );

        // The service of a topic drops its receiver when we unsubscribe from the topic.
        receivers.receivers.remove(&heze_fork_digest);
        assert_eq!(
            senders.new_payload(payload(HEZE_EPOCH)),
            Err(PayloadDisseminationError::Unsubscribed)
        );
        assert_eq!(senders.new_payload(payload(BPO_EPOCH)), Ok(()));
    }

    #[test]
    fn fork_digests_that_are_over_have_no_topic() {
        let fork_context = fork_context(BPO_EPOCH + 5);
        let bpo_fork_digest = fork_context.context_bytes(Epoch::new(BPO_EPOCH));
        let (senders, mut receivers) = PayloadDisseminationSenders::<E>::new(&fork_context);

        assert_eq!(
            receivers.receivers.keys().collect::<Vec<_>>(),
            vec![&bpo_fork_digest]
        );
        // The payload is not routed to the topic of another fork digest.
        assert_eq!(
            senders.new_payload(payload(BPO_EPOCH - 1)),
            Err(PayloadDisseminationError::NoTopic)
        );
        assert_eq!(senders.new_payload(payload(BPO_EPOCH + 5)), Ok(()));
        assert_eq!(
            queued_payloads(&mut receivers, bpo_fork_digest),
            vec![slot(BPO_EPOCH + 5)]
        );
    }

    #[test]
    fn disabled_senders_have_no_topic() {
        assert_eq!(
            PayloadDisseminationSenders::<E>::disabled().new_payload(payload(HEZE_EPOCH)),
            Err(PayloadDisseminationError::NoTopic)
        );
    }
}

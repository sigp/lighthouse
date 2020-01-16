//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and determines whether attestations should be aggregated and/or passed to the beacon node.

use crate::error;
use crate::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::topics::ATTESTATION_SUBNET_COUNT;
use eth2_libp2p::SubnetId;
use futures::prelude::*;
use hashmap_delay::HashMapDelay;
use slog::{debug, o, trace};
use std::boxed::Box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use types::{Attestation, EthSpec};

/// The number of epochs in advance we try to discover peers for a shard subnet.
const EPOCHS_TO_DISCOVER_PEERS: u8 = 1;

pub enum AttestationServiceMessage<T: EthSpec> {
    /// A raw attestation has been received
    Attestation(SubnetId, Box<Attestation<T>>),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// A channel to the network service, for instructing the network service to
    /// subscribe/unsubscribe from various shard subnets.
    network_send: mpsc::UnboundedSender<NetworkMessage>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// A timeout list for when to start searching for peers for a particular shard.
    discover_peers: HashMapDelay<SubnetId, Instant>,

    /// A timeout list for when to subscribe to a shard subnet.
    subscriptions: HashMapDelay<SubnetId, Instant>,

    /// A timeout list for when to unsubscribe from a shard subnet.
    unsubscriptions: HashMapDelay<SubnetId, Instant>,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<AttestationServiceMessage<T::EthSpec>>> {
        let log = log.new(o!("service" => "attestation_service"));

        trace!(log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        // generate the Message handler
        let mut service = AttestationService {
            network_send,
            beacon_chain,
            discover_peers: HashMapDelay::default(),
            subscriptions: HashMapDelay::default(),
            unsubscriptions: HashMapDelay::default(),
            log,
        };

        let main_task = {
            service
                .discover_peers
                .for_each(|discover| Ok(service.handle_discover_peer(discover)))
                /*
                .select(
                    self.subsciptions
                        .for_each(|sub| self.handle_subscriptions(sub)),
                )
                */
                .map_err(|_| {
                    debug!(service.log, "Attestation Service terminated.");
                })
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(main_task);

        Ok(handler_send)
    }

    fn handle_discover_peer(&mut self, discover: (SubnetId, Instant)) {}

    fn handle_subscriptions(&mut self, discover: (SubnetId, Instant)) {}
}

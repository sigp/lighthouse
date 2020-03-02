//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use crate::error;
use crate::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::topics::ATTESTATION_SUBNET_COUNT;
use eth2_libp2p::SubnetId;
use futures::prelude::*;
use hashmap_delay::HashMapDelay;
use slog::{debug, error, o, trace};
use std::boxed::Box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use std::collections::VecDeque;
use types::{Attestation};
use rest_types::ValidatorSubscriptions;

/// The number of epochs in advance we try to discover peers for a shard subnet.
const EPOCHS_TO_DISCOVER_PEERS: u8 = 1;
/// The number of random subnets to be connected to per validator.
const RANDOM_SUBNETS_PER_VALIDATOR: u8 = 1;
/// The minimum number of epochs to remain subscribed to a random subnet.
const EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION: u16 = 256;

pub enum AttServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(SubnetId),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(SubnetId),
    /// Discover peers for a particular subnet.
    DiscoverPeers(SubnetId),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    queued_events: VecDeque<AttServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets.
    random_subnets: HashMapDelay<SubnetId, ()>,

    /// A collection of timeouts for when to start searching for peers for a particular shard.
    discover_peers: HashMapDelay<SubnetId, Instant>,

    /// A collection of timeouts for when to subscribe to a shard subnet.
    subscriptions: HashMapDelay<SubnetId, Instant>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashMapDelay<SubnetId, Instant>,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    pub fn new( beacon_chain: Arc<BeaconChain<T>>, log: &slog::Logger) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        // generate the Message handler
        AttestationService {
            queued_events: VecDeque::with_capacity(10),
            beacon_chain,
            random_subnets: HashMapDelay::default(),
            discover_peers: HashMapDelay::default(),
            subscriptions: HashMapDelay::default(),
            unsubscriptions: HashMapDelay::default(),
            log,
        }
    }

    /// It is time to run a discovery query to find peers for a particular subnet.
    fn handle_discover_peer(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Searching for peers for subnet"; "subnet" => *subnet_id);
        self.queued_events.push_back(AttServiceMessage::DiscoverPeers(subnet_id));
    }

    fn handle_subscriptions(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Subscribing to subnet"; "subnet" => *subnet_id);
        self.queued_events.push_back(AttServiceMessage::Subscribe(subnet_id));
    }

    fn handle_persistant_subnets(&mut self, _subnet: (SubnetId, ())) {}

    fn handle_attestation(&mut self, subnet: SubnetId, attestation: Box<Attestation<T::EthSpec>>) {}

    pub fn handle_validator_subscriptions(&mut self, subscriptions: ValidatorSubscriptions) {



    }
}

impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = AttServiceMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

                // handle any discovery events
                while let Async::Ready(Some((subnet_id, _))) =
                    self.discover_peers.poll().map_err(|e| {
                        error!(self.log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_discover_peer(subnet_id);
                }

                while let Async::Ready(Some((subnet_id, _))) = self.subscriptions.poll().map_err(|e| {
                        error!(self.log, "Failed to check for subnet subscription times"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_subscriptions(subnet_id);
                }

                while let Async::Ready(Some(subnet)) = self.random_subnets.poll().map_err(|e| { 
                        error!(self.log, "Failed to check for random subnet cycles"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_persistant_subnets(subnet);
                }

                // process any generated events
                if let Some(event) = self.queued_events.pop_front() {
                    return Ok(Async::Ready(Some(event)));
                }

                Ok(Async::NotReady)
        }
}



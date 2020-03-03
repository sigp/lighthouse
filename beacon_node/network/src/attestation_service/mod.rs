//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::prelude::*;
use hashmap_delay::HashSetDelay;
use slog::{debug, error, o, warn, trace};
use std::boxed::Box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use std::collections::VecDeque;
use types::{Attestation, SubnetId};
use rest_types::ValidatorSubscription;
use rand::seq::SliceRandom;
use eth2_libp2p::{NetworkGlobals, types::GossipKind};
use types::{EthSpec};
use slot_clock::SlotClock;

/// The number of random subnets to be connected to per validator.
const RANDOM_SUBNETS_PER_VALIDATOR: u8 = 1;
/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
const PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 5;
/// The time (in seconds) before a last seen validator is considered absent and we unsubscribe from the random
/// gossip topics that we subscribed to due to the validator connection.
const LAST_SEEN_VALIDATOR_TIMEOUT: u64 = 1800; // 30 mins
/// The number of seconds in advance that we subscribe to a subnet before the required slot.
const ADVANCE_SUBSCRIBE_SECS: u64 = 3;

pub enum AttServiceMessage {
    /// Subscribe to the specified subnet id.
    Subscribe(SubnetId),
    /// Add the `SubnetId` to the ENR bitfield.
    ENRAdd(SubnetId),
    /// Remove the `SubnetId` from the ENR bitfield.
    ENRRemove(SubnetId),
    /// Unsubscribe to the specified subnet id.
    Unsubscribe(SubnetId),
    /// Discover peers for a particular subnet.
    DiscoverPeers(SubnetId),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<AttServiceMessage>,

    /// A collection of public network variables.
    network_globals: Arc<NetworkGlobals>,

    /// A reference to the beacon chain to process received attestations.
    beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets mapped to their expiry deadline.
    random_subnets: HashSetDelay<SubnetId>,

    /// A collection of timeouts for when to start searching for peers for a particular shard.
    discover_peers: HashSetDelay<SubnetId>,

    /// A collection of timeouts for when to subscribe to a shard subnet.
    subscriptions: HashSetDelay<SubnetId>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashSetDelay<SubnetId>,

    /// A collection of seen validators. These dictate how many random subnets we should be
    /// subscribed to. As these time out, we unsubscribe for the required random subnets and update
    /// our ENR.
    /// This is a set of validator indices.
    known_validators: HashSetDelay<u64>, 

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, network_globals: Arc<NetworkGlobals>, log: &slog::Logger) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        // calculate the random subnet duration from the spec constants
        let spec = &beacon_chain.spec;
        let random_subnet_duration_millis = spec.epochs_per_random_subnet_subscription.saturating_mul(T::EthSpec::slots_per_epoch()).saturating_mul(spec.milliseconds_per_slot);

        // generate the AttestationService
        AttestationService {
            events: VecDeque::with_capacity(10),
            network_globals,
            beacon_chain,
            random_subnets: HashSetDelay::new(Duration::from_millis(random_subnet_duration_millis)),
            discover_peers: HashSetDelay::default(),
            subscriptions: HashSetDelay::default(),
            unsubscriptions: HashSetDelay::default(),
            known_validators: HashSetDelay::new(Duration::from_secs(LAST_SEEN_VALIDATOR_TIMEOUT)),
            log,
        }
    }

    /// It is time to run a discovery query to find peers for a particular subnet.
    fn handle_discover_peer(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Searching for peers for subnet"; "subnet" => *subnet_id);
        self.events.push_back(AttServiceMessage::DiscoverPeers(subnet_id));
    }

    fn handle_subscriptions(&mut self, subnet_id: SubnetId) {
        debug!(self.log, "Subscribing to subnet"; "subnet" => *subnet_id);
        self.events.push_back(AttServiceMessage::Subscribe(subnet_id));
    }

    fn handle_persistant_subnets(&mut self, _subnet: SubnetId) {}

    fn handle_attestation(&mut self, subnet: SubnetId, attestation: Box<Attestation<T::EthSpec>>) {}

    pub fn handle_validator_subscriptions(&mut self, subscriptions: Vec<ValidatorSubscription>) -> Result<(),()> {

        let current_state = self.beacon_chain.head().map_err(|e| ())?.beacon_state;

        for subscription in subscriptions {
            // first check that the validator exists - here we assume all subscriptions
            // have been verified before reaching this service
            if let Ok(pubkey) = current_state.get_validator_pubkey(subscription.validator_index) {

                // Registers the validator with the attestation service.
                // This will subscribe to long-lived random subnets if required.
                self.add_known_validator(subscription.validator_index);

                // determine if we should run a discovery lookup request
                if subscription.slot >= current_state.slot.saturating_add(PEER_DISCOVERY_SLOT_LOOK_AHEAD) {
                    // start searching for peers for the subnet
                    let subnet_id =  SubnetId::new(subscription.attestation_committee_index % self.beacon_chain.spec.attestation_subnet_count);
                    self.events.push_back(AttServiceMessage::DiscoverPeers(subnet_id));
                }

            let slot_duration = Duration::from_millis(self.beacon_chain.spec.milliseconds_per_slot);
                // calculate the time to subscribe to the subnet
                let duration_to_subscribe = {
                    let duration_to_next_slot = self.beacon_chain.slot_clock.duration_to_next_slot().ok_or_else(|| {
                        warn!(self.log, "Unable to determine duration to next slot");})?;
                     
                
                // set a timer to subscribe to the subnet

                };

            }

        }

        Ok(())
    }

    /// Updates the known_validators mapping and subscribes to a set of random subnets if required. 
    /// 
    /// This also updates the ENR to indicate our long-lived subscription to the subnet
    fn add_known_validator(&mut self, validator_index: u64) {
        if self.known_validators.get(&validator_index).is_none() {
            // New validator has subscribed
            // Subscribe to random topics and update the ENR if needed.
           
            let spec = &self.beacon_chain.spec;

            if self.random_subnets.len() < spec.attestation_subnet_count as usize {
                // Still room for subscriptions
                self.subscribe_to_random_subnets(self.beacon_chain.spec.random_subnets_per_validator as usize);
            }
        }
        // add the new validator or update the current timeout for a known validator
        self.known_validators.insert(validator_index);
    }

    /// Subscribe to long-lived random subnets and update the local ENR bitfield.
    fn subscribe_to_random_subnets(&mut self, mut no_subnets_to_subscribe: usize) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;

        // Build a list of random subnets that we are not currently subscribed to.
        let available_subnets = (0..subnet_count).map(SubnetId::new).filter(|subnet_id| self.random_subnets.get(subnet_id).is_none()).collect::<Vec<_>>();

        let to_subscribe_subnets = {
        if available_subnets.len() < no_subnets_to_subscribe  {
            debug!(self.log, "Reached maximum random subnet subscriptions");
            no_subnets_to_subscribe = available_subnets.len();
            available_subnets
        } else {
        // select a random sample of available subnets
        available_subnets.choose_multiple(&mut rand::thread_rng(), no_subnets_to_subscribe).cloned().collect::<Vec<_>>()
        }
        };

        for subnet_id in to_subscribe_subnets {
            // remove this subnet from any immediate subscription/un-subscription events
            self.subscriptions.remove(&subnet_id);
            self.unsubscriptions.remove(&subnet_id);

            // This inserts a new random subnet
            self.random_subnets.insert(subnet_id);

            // if we are not already subscribed, then subscribe
            let topic_kind = &GossipKind::CommitteeIndex(subnet_id); 

            if let None = self.network_globals.gossipsub_subscriptions.read().iter().find(|topic| topic.kind() == topic_kind) {
                // Not already subscribed to the topic
                self.events.push_back(AttServiceMessage::Subscribe(subnet_id));
            }
            // add the subnet to the ENR bitfield
            self.events.push_back(AttServiceMessage::ENRAdd(subnet_id));
        }
    }
}


impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = AttServiceMessage;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {

                // handle any discovery events
                while let Async::Ready(Some(subnet_id)) =
                    self.discover_peers.poll().map_err(|e| {
                        error!(self.log, "Failed to check for peer discovery requests"; "error"=> format!("{}", e));
                    })?
                {
                    self.handle_discover_peer(subnet_id);
                }

                while let Async::Ready(Some(subnet_id)) = self.subscriptions.poll().map_err(|e| {
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
                if let Some(event) = self.events.pop_front() {
                    return Ok(Async::Ready(Some(event)));
                }

                Ok(Async::NotReady)
        }
}



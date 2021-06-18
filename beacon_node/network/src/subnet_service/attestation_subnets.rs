//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use super::SubnetServiceMessage;
use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::prelude::*;
use rand::seq::SliceRandom;
use slog::{debug, error, o, trace, warn};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{NetworkConfig, Subnet, SubnetDiscovery};
use hashset_delay::HashSetDelay;
use slot_clock::SlotClock;
use types::{Attestation, EthSpec, Slot, SubnetId, ValidatorSubscription};

use crate::metrics;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes atmost 30 secs, 2 slots take 24s.
const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;
/// The time (in slots) before a last seen validator is considered absent and we unsubscribe from the random
/// gossip topics that we subscribed to due to the validator connection.
const LAST_SEEN_VALIDATOR_TIMEOUT: u32 = 150;
/// The fraction of a slot that we subscribe to a subnet before the required slot.
///
/// Note: The time is calculated as `time = seconds_per_slot / ADVANCE_SUBSCRIPTION_TIME`.
const ADVANCE_SUBSCRIBE_TIME: u32 = 3;
/// The default number of slots before items in hash delay sets used by this class should expire.
///  36s at 12s slot time
const DEFAULT_EXPIRATION_TIMEOUT: u32 = 3;

/// A particular subnet at a given slot.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ExactSubnet {
    /// The `SubnetId` associated with this subnet.
    pub subnet_id: SubnetId,
    /// The `Slot` associated with this subnet.
    pub slot: Slot,
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of currently subscribed random subnets mapped to their expiry deadline.
    pub(crate) random_subnets: HashSetDelay<SubnetId>,

    /// The collection of all currently subscribed subnets (long-lived **and** short-lived).
    subscriptions: HashSet<SubnetId>,

    /// A collection of timeouts for when to unsubscribe from a shard subnet.
    unsubscriptions: HashSetDelay<ExactSubnet>,

    /// A collection timeouts to track the existence of aggregate validator subscriptions at an `ExactSubnet`.
    aggregate_validators_on_subnet: HashSetDelay<ExactSubnet>,

    /// A collection of seen validators. These dictate how many random subnets we should be
    /// subscribed to. As these time out, we unsubscribe for the required random subnets and update
    /// our ENR.
    /// This is a set of validator indices.
    known_validators: HashSetDelay<u64>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The discovery mechanism of lighthouse is disabled.
    discovery_disabled: bool,

    /// We are always subscribed to all subnets.
    subscribe_all_subnets: bool,

    /// We process and aggregate all attestations on subscribed subnets.
    import_all_attestations: bool,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    /* Public functions */

    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        // calculate the random subnet duration from the spec constants
        let spec = &beacon_chain.spec;
        let slot_duration = beacon_chain.slot_clock.slot_duration();
        let random_subnet_duration_millis = spec
            .epochs_per_random_subnet_subscription
            .saturating_mul(T::EthSpec::slots_per_epoch())
            .saturating_mul(slot_duration.as_millis() as u64);

        // Panics on overflow. Ensure LAST_SEEN_VALIDATOR_TIMEOUT is not too large.
        let last_seen_val_timeout = slot_duration
            .checked_mul(LAST_SEEN_VALIDATOR_TIMEOUT)
            .expect("LAST_SEEN_VALIDATOR_TIMEOUT must not be ridiculously large");
        let default_timeout = slot_duration
            .checked_mul(DEFAULT_EXPIRATION_TIMEOUT)
            .expect("DEFAULT_EXPIRATION_TIMEOUT must not be ridiculoustly large");

        AttestationService {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            random_subnets: HashSetDelay::new(Duration::from_millis(random_subnet_duration_millis)),
            subscriptions: HashSet::new(),
            unsubscriptions: HashSetDelay::new(default_timeout),
            aggregate_validators_on_subnet: HashSetDelay::new(default_timeout),
            known_validators: HashSetDelay::new(last_seen_val_timeout),
            waker: None,
            subscribe_all_subnets: config.subscribe_all_subnets,
            import_all_attestations: config.import_all_attestations,
            discovery_disabled: config.disable_discovery,
            log,
        }
    }

    /// Return count of all currently subscribed subnets (long-lived **and** short-lived).
    #[cfg(test)]
    pub fn subscription_count(&self) -> usize {
        if self.subscribe_all_subnets {
            self.beacon_chain.spec.attestation_subnet_count as usize
        } else {
            self.subscriptions.len()
        }
    }

    /// Processes a list of validator subscriptions.
    ///
    /// This will:
    /// - Register new validators as being known.
    /// - Subscribe to the required number of random subnets.
    /// - Update the local ENR for new random subnets due to seeing new validators.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(
        &mut self,
        subscriptions: Vec<ValidatorSubscription>,
    ) -> Result<(), String> {
        // Maps each subnet_id subscription to it's highest slot
        let mut subnets_to_discover: HashMap<SubnetId, Slot> = HashMap::new();
        for subscription in subscriptions {
            metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_REQUESTS);
            //NOTE: We assume all subscriptions have been verified before reaching this service

            // Registers the validator with the attestation service.
            // This will subscribe to long-lived random subnets if required.
            trace!(self.log,
                "Validator subscription";
                "subscription" => ?subscription,
            );
            self.add_known_validator(subscription.validator_index);

            let subnet_id = match SubnetId::compute_subnet::<T::EthSpec>(
                subscription.slot,
                subscription.attestation_committee_index,
                subscription.committee_count_at_slot,
                &self.beacon_chain.spec,
            ) {
                Ok(subnet_id) => subnet_id,
                Err(e) => {
                    warn!(self.log,
                        "Failed to compute subnet id for validator subscription";
                        "error" => ?e,
                        "validator_index" => subscription.validator_index
                    );
                    continue;
                }
            };
            // Ensure each subnet_id inserted into the map has the highest slot as it's value.
            // Higher slot corresponds to higher min_ttl in the `SubnetDiscovery` entry.
            if let Some(slot) = subnets_to_discover.get(&subnet_id) {
                if subscription.slot > *slot {
                    subnets_to_discover.insert(subnet_id, subscription.slot);
                }
            } else if !self.discovery_disabled {
                subnets_to_discover.insert(subnet_id, subscription.slot);
            }

            let exact_subnet = ExactSubnet {
                subnet_id,
                slot: subscription.slot,
            };

            // Determine if the validator is an aggregator. If so, we subscribe to the subnet and
            // if successful add the validator to a mapping of known aggregators for that exact
            // subnet.

            if subscription.is_aggregator {
                metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS);
                // set the subscription timer to subscribe to the next subnet if required
                if let Err(e) = self.subscribe_to_subnet(exact_subnet.clone()) {
                    warn!(self.log,
                        "Subscription to subnet error";
                        "error" => e,
                        "validator_index" => subscription.validator_index,
                    );
                } else {
                    trace!(self.log,
                        "Subscribed to subnet for aggregator duties";
                        "exact_subnet" => ?exact_subnet,
                        "validator_index" => subscription.validator_index
                    );
                }
            }
        }

        // If the discovery mechanism isn't disabled, attempt to set up a peer discovery for the
        // required subnets.
        if !self.discovery_disabled {
            if let Err(e) = self.discover_peers_request(
                subnets_to_discover
                    .into_iter()
                    .map(|(subnet_id, slot)| ExactSubnet { subnet_id, slot }),
            ) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            };
        }

        // pre-emptively wake the thread to check for new events
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
        Ok(())
    }

    /// Checks if we have subscribed aggregate validators for the subnet. If not, checks the gossip
    /// verification, re-propagates and returns false.
    pub fn should_process_attestation(
        &self,
        subnet: SubnetId,
        attestation: &Attestation<T::EthSpec>,
    ) -> bool {
        if self.import_all_attestations {
            return true;
        }

        let exact_subnet = ExactSubnet {
            subnet_id: subnet,
            slot: attestation.data.slot,
        };
        self.aggregate_validators_on_subnet.contains(&exact_subnet)
    }

    /* Internal private functions */

    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request.
    ///
    /// If there is sufficient time, queues a peer discovery request for all the required subnets.
    fn discover_peers_request(
        &mut self,
        exact_subnets: impl Iterator<Item = ExactSubnet>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let discovery_subnets: Vec<SubnetDiscovery> = exact_subnets
            .filter_map(|exact_subnet| {
                // check if there is enough time to perform a discovery lookup
                if exact_subnet.slot
                    >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD)
                {
                    // if the slot is more than epoch away, add an event to start looking for peers
                    // add one slot to ensure we keep the peer for the subscription slot
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(exact_subnet.slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery {
                        subnet: Subnet::Attestation(exact_subnet.subnet_id),
                        min_ttl,
                    })
                } else {
                    // We may want to check the global PeerInfo to see estimated timeouts for each
                    // peer before they can be removed.
                    warn!(self.log,
                        "Not enough time for a discovery search";
                        "subnet_id" => ?exact_subnet
                    );
                    None
                }
            })
            .collect();

        if !discovery_subnets.is_empty() {
            self.events
                .push_back(SubnetServiceMessage::DiscoverPeers(discovery_subnets));
        }
        Ok(())
    }

    /// Checks the current random subnets and subscriptions to determine if a new subscription for this
    /// subnet is required for the given slot.
    ///
    /// If required, adds a subscription event and an associated unsubscription event.
    fn subscribe_to_subnet(&mut self, exact_subnet: ExactSubnet) -> Result<(), &'static str> {
        // initialise timing variables
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        // Calculate the duration to the unsubscription event.
        // There are two main cases. Attempting to subscribe to the current slot and all others.
        let expected_end_subscription_duration = if current_slot >= exact_subnet.slot {
            self.beacon_chain
                .slot_clock
                .duration_to_next_slot()
                .ok_or("Unable to determine duration to next slot")?
        } else {
            let slot_duration = self.beacon_chain.slot_clock.slot_duration();

            // the duration until we no longer need this subscription. We assume a single slot is
            // sufficient.
            self.beacon_chain
                .slot_clock
                .duration_to_slot(exact_subnet.slot)
                .ok_or("Unable to determine duration to subscription slot")?
                + slot_duration
        };

        // Regardless of whether or not we have already subscribed to a subnet, track the expiration
        // of aggregate validator subscriptions to exact subnets so we know whether or not to drop
        // attestations for a given subnet + slot
        self.aggregate_validators_on_subnet
            .insert_at(exact_subnet.clone(), expected_end_subscription_duration);

        // Checks on current subscriptions
        // Note: We may be connected to a long-lived random subnet. In this case we still add the
        // subscription timeout and check this case when the timeout fires. This is because a
        // long-lived random subnet can be unsubscribed at any time when a validator becomes
        // in-active. This case is checked on the subscription event (see `handle_subscriptions`).

        // Return if we already have a subscription for this subnet_id and slot
        if self.unsubscriptions.contains(&exact_subnet) || self.subscribe_all_subnets {
            return Ok(());
        }

        // We are not currently subscribed and have no waiting subscription, create one
        self.handle_subscriptions(exact_subnet.clone());

        // if there is an unsubscription event for the slot prior, we remove it to prevent
        // unsubscriptions immediately after the subscription. We also want to minimize
        // subscription churn and maintain a consecutive subnet subscriptions.
        self.unsubscriptions.retain(|subnet| {
            !(subnet.subnet_id == exact_subnet.subnet_id && subnet.slot <= exact_subnet.slot)
        });
        // add an unsubscription event to remove ourselves from the subnet once completed
        self.unsubscriptions
            .insert_at(exact_subnet, expected_end_subscription_duration);
        Ok(())
    }

    /// Updates the `known_validators` mapping and subscribes to a set of random subnets if required.
    ///
    /// This also updates the ENR to indicate our long-lived subscription to the subnet
    fn add_known_validator(&mut self, validator_index: u64) {
        if self.known_validators.get(&validator_index).is_none() && !self.subscribe_all_subnets {
            // New validator has subscribed
            // Subscribe to random topics and update the ENR if needed.

            let spec = &self.beacon_chain.spec;

            if self.random_subnets.len() < spec.attestation_subnet_count as usize {
                // Still room for subscriptions
                self.subscribe_to_random_subnets(
                    self.beacon_chain.spec.random_subnets_per_validator as usize,
                );
            }
        }
        // add the new validator or update the current timeout for a known validator
        self.known_validators.insert(validator_index);
    }

    /// Subscribe to long-lived random subnets and update the local ENR bitfield.
    fn subscribe_to_random_subnets(&mut self, no_subnets_to_subscribe: usize) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;

        // Build a list of random subnets that we are not currently subscribed to.
        let available_subnets = (0..subnet_count)
            .map(SubnetId::new)
            .filter(|subnet_id| self.random_subnets.get(subnet_id).is_none())
            .collect::<Vec<_>>();

        let to_subscribe_subnets = {
            if available_subnets.len() < no_subnets_to_subscribe {
                debug!(self.log, "Reached maximum random subnet subscriptions");
                available_subnets
            } else {
                // select a random sample of available subnets
                available_subnets
                    .choose_multiple(&mut rand::thread_rng(), no_subnets_to_subscribe)
                    .cloned()
                    .collect::<Vec<_>>()
            }
        };

        for subnet_id in to_subscribe_subnets {
            // remove this subnet from any immediate un-subscription events
            self.unsubscriptions
                .retain(|exact_subnet| exact_subnet.subnet_id != subnet_id);

            // insert a new random subnet
            self.random_subnets.insert(subnet_id);

            // send discovery request
            // Note: it's wasteful to send a DiscoverPeers request if we already have peers for this subnet.
            // However, subscribing to random subnets ideally shouldn't happen very often (once in ~27 hours) and
            // this makes it easier to deterministically test the attestations service.
            self.events
                .push_back(SubnetServiceMessage::DiscoverPeers(vec![SubnetDiscovery {
                    subnet: Subnet::Attestation(subnet_id),
                    min_ttl: None,
                }]));

            // if we are not already subscribed, then subscribe
            if !self.subscriptions.contains(&subnet_id) {
                self.subscriptions.insert(subnet_id);
                debug!(self.log, "Subscribing to random subnet"; "subnet_id" => ?subnet_id);
                self.events
                    .push_back(SubnetServiceMessage::Subscribe(Subnet::Attestation(
                        subnet_id,
                    )));
            }

            // add the subnet to the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrAdd(Subnet::Attestation(subnet_id)));
        }
    }

    /* A collection of functions that handle the various timeouts */

    /// A queued subscription is ready.
    ///
    /// We add subscriptions events even if we are already subscribed to a random subnet (as these
    /// can be unsubscribed at any time by inactive validators). If we are
    /// still subscribed at the time the event fires, we don't re-subscribe.
    fn handle_subscriptions(&mut self, exact_subnet: ExactSubnet) {
        // Check if the subnet currently exists as a long-lasting random subnet
        if let Some(expiry) = self.random_subnets.get(&exact_subnet.subnet_id) {
            // we are subscribed via a random subnet, if this is to expire during the time we need
            // to be subscribed, just extend the expiry
            let slot_duration = self.beacon_chain.slot_clock.slot_duration();
            let advance_subscription_duration = slot_duration
                .checked_div(ADVANCE_SUBSCRIBE_TIME)
                .expect("ADVANCE_SUBSCRIPTION_TIME cannot be too large");
            // we require the subnet subscription for at least a slot on top of the initial
            // subscription time
            let expected_end_subscription_duration = slot_duration + advance_subscription_duration;

            if expiry < &(Instant::now() + expected_end_subscription_duration) {
                self.random_subnets
                    .update_timeout(&exact_subnet.subnet_id, expected_end_subscription_duration);
            }
        } else {
            // we are also not un-subscribing from a subnet if the next slot requires us to be
            // subscribed. Therefore there could be the case that we are already still subscribed
            // to the required subnet. In which case we do not issue another subscription request.
            if !self.subscriptions.contains(&exact_subnet.subnet_id) {
                // we are not already subscribed
                debug!(self.log, "Subscribing to subnet"; "subnet" => *exact_subnet.subnet_id, "target_slot" => exact_subnet.slot.as_u64());
                self.subscriptions.insert(exact_subnet.subnet_id);
                self.events
                    .push_back(SubnetServiceMessage::Subscribe(Subnet::Attestation(
                        exact_subnet.subnet_id,
                    )));
            }
        }
    }

    /// A queued unsubscription is ready.
    ///
    /// Unsubscription events are added, even if we are subscribed to long-lived random subnets. If
    /// a random subnet is present, we do not unsubscribe from it.
    fn handle_unsubscriptions(&mut self, exact_subnet: ExactSubnet) {
        // Check if the subnet currently exists as a long-lasting random subnet
        if self.random_subnets.contains(&exact_subnet.subnet_id) {
            return;
        }

        debug!(self.log, "Unsubscribing from subnet"; "subnet" => *exact_subnet.subnet_id, "processed_slot" => exact_subnet.slot.as_u64());

        self.subscriptions.remove(&exact_subnet.subnet_id);
        self.events
            .push_back(SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                exact_subnet.subnet_id,
            )));
    }

    /// A random subnet has expired.
    ///
    /// This function selects a new subnet to join, or extends the expiry if there are no more
    /// available subnets to choose from.
    fn handle_random_subnet_expiry(&mut self, subnet_id: SubnetId) {
        let subnet_count = self.beacon_chain.spec.attestation_subnet_count;
        if self.random_subnets.len() == (subnet_count - 1) as usize {
            // We are at capacity, simply increase the timeout of the current subnet
            self.random_subnets.insert(subnet_id);
            return;
        }
        // If there are no unsubscription events for `subnet_id`, we unsubscribe immediately.
        if !self
            .unsubscriptions
            .keys()
            .any(|s| s.subnet_id == subnet_id)
        {
            // we are not at capacity, unsubscribe from the current subnet.
            debug!(self.log, "Unsubscribing from random subnet"; "subnet_id" => *subnet_id);
            self.events
                .push_back(SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                    subnet_id,
                )));
        }

        // Remove the ENR bitfield bit and choose a new random on from the available subnets
        self.events
            .push_back(SubnetServiceMessage::EnrRemove(Subnet::Attestation(
                subnet_id,
            )));
        // Subscribe to a new random subnet
        self.subscribe_to_random_subnets(1);
    }

    /// A known validator has not sent a subscription in a while. They are considered offline and the
    /// beacon node no longer needs to be subscribed to the allocated random subnets.
    ///
    /// We don't keep track of a specific validator to random subnet, rather the ratio of active
    /// validators to random subnets. So when a validator goes offline, we can simply remove the
    /// allocated amount of random subnets.
    fn handle_known_validator_expiry(&mut self) {
        let spec = &self.beacon_chain.spec;
        let subnet_count = spec.attestation_subnet_count;
        let random_subnets_per_validator = spec.random_subnets_per_validator;
        if self.known_validators.len() as u64 * random_subnets_per_validator >= subnet_count {
            // have too many validators, ignore
            return;
        }

        let subscribed_subnets = self.random_subnets.keys().cloned().collect::<Vec<_>>();
        let to_remove_subnets = subscribed_subnets.choose_multiple(
            &mut rand::thread_rng(),
            random_subnets_per_validator as usize,
        );

        for subnet_id in to_remove_subnets {
            // If there are no unsubscription events for `subnet_id`, we unsubscribe immediately.
            if !self
                .unsubscriptions
                .keys()
                .any(|s| s.subnet_id == *subnet_id)
            {
                self.events
                    .push_back(SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                        *subnet_id,
                    )));
            }
            // as the long lasting subnet subscription is being removed, remove the subnet_id from
            // the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrRemove(Subnet::Attestation(
                    *subnet_id,
                )));
            self.random_subnets.remove(subnet_id);
        }
    }
}

impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = SubnetServiceMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // update the waker if needed
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        // process any un-subscription events
        match self.unsubscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(exact_subnet))) => self.handle_unsubscriptions(exact_subnet),
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for subnet unsubscription times"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // process any random subnet expiries
        match self.random_subnets.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(subnet))) => self.handle_random_subnet_expiry(subnet),
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for random subnet cycles"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // process any known validator expiries
        match self.known_validators.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(_validator_index))) => {
                let _ = self.handle_known_validator_expiry();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for random subnet cycles"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }
        // poll to remove entries on expiration, no need to act on expiration events
        if let Poll::Ready(Some(Err(e))) = self.aggregate_validators_on_subnet.poll_next_unpin(cx) {
            error!(self.log, "Failed to check for aggregate validator on subnet expirations"; "error"=> e);
        }

        // process any generated events
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        Poll::Pending
    }
}

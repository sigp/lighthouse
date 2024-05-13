//! This service keeps track of which shard subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to shard subnets, requests peer discoveries and
//! determines whether attestations should be aggregated and/or passed to the beacon node.

use super::SubnetServiceMessage;
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use delay_map::{HashMapDelay, HashSetDelay};
use futures::prelude::*;
use lighthouse_network::{discv5::enr::NodeId, NetworkConfig, Subnet, SubnetDiscovery};
use slog::{debug, error, info, o, trace, warn};
use slot_clock::SlotClock;
use types::{
    Attestation, EthSpec, Slot, SubnetId, SyncCommitteeSubscription, SyncSubnetId, Unsigned,
    ValidatorSubscription,
};

use crate::metrics;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes at most 30 secs, 2 slots take 24s.
pub(crate) const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;
/// The fraction of a slot that we subscribe to a subnet before the required slot.
///
/// Currently a whole slot ahead.
const ADVANCE_SUBSCRIBE_SLOT_FRACTION: u32 = 1;

/// A particular subnet at a given slot.
#[derive(PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub struct ExactSubnet {
    /// The `SubnetId` associated with this subnet.
    pub subnet_id: Subnet,
    /// For Attestations, this slot represents the start time at which we need to subscribe to the
    /// slot. For SyncCommittee subnet id's this represents the end slot at which we no longer need
    /// to subscribe to the subnet.
    // NOTE: There was different logic between the two subscriptions and having a different
    // interpretation of this variable seemed like the best way to group the logic, even though it
    // may be counter-intuitive (apologies to future readers).
    pub slot: Slot,
}

/// The enum used to group all kinds of validator subscriptions
pub enum Subscription {
    Attestation(ValidatorSubscription),
    SyncCommittee(SyncCommitteeSubscription),
}

pub struct AttestationService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// Subnets we are currently subscribed to as short lived subscriptions.
    ///
    /// Once they expire, we unsubscribe from these.
    /// We subscribe to subnets when we are an aggregator for an exact subnet.
    // NOTE: When setup the defalut timeout is set for sync committee subscriptions.
    subscriptions: HashMapDelay<Subnet, Slot>,

    /// A list of permanent subnets that this node is subscribed to.
    // TODO: Shift this to a dynamic bitfield
    permanent_attestation_subscriptions: HashSet<SubnetId>,

    /// A collection of timeouts for when to unsubscirbe from a sync committee subnet.
    // sync_unsubscriptions: HashSetDelay<SyncSubnetId>,

    /// Subscriptions that need to be executed in the future.
    scheduled_subscriptions: HashSetDelay<ExactSubnet>,

    /// A collection timeouts to track the existence of aggregate validator subscriptions at an
    /// `ExactSubnet`.
    aggregate_validators_on_subnet: Option<HashSetDelay<ExactSubnet>>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The discovery mechanism of lighthouse is disabled.
    discovery_disabled: bool,

    /// We are always subscribed to all subnets.
    subscribe_all_subnets: bool,

    /// Whether this node is a block proposer-only node.
    proposer_only: bool,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService<T> {
    /* Public functions */

    /// Establish the service based on the passed configuration.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        node_id: NodeId,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "attestation_service"));

        let slot_duration = beacon_chain.slot_clock.slot_duration();

        if config.subscribe_all_subnets {
            slog::info!(log, "Subscribing to all subnets");
        }

        // Build the list of known permanent subscriptions, so that we know not to subscribe or
        // discover them.
        let mut permanent_attestation_subscriptions = HashSet::default();
        if config.subscribe_all_subnets {
            // We are subscribed to all subnets, set all the bits to true.
            for index in 0..<T::EthSpec as EthSpec>::SubnetBitfieldLength::to_u64() {
                permanent_attestation_subscriptions.insert(SubnetId::from(index));
            }
        } else {
            // Not subscribed to all subnets, so just calculate the required subnets from the
            for subnet_id in SubnetId::compute_attestation_subnets::<T::EthSpec>(
                node_id.raw().into(),
                &beacon_chain.spec,
            ) {
                permanent_attestation_subscriptions.insert(subnet_id);
            }
        }

        // Set up the sync committee subscriptions
        let spec = &beacon_chain.spec;
        let epoch_duration_secs =
            beacon_chain.slot_clock.slot_duration().as_secs() * T::EthSpec::slots_per_epoch();
        let default_sync_committee_duration = Duration::from_secs(
            epoch_duration_secs.saturating_mul(spec.epochs_per_sync_committee_period.as_u64()),
        );

        let track_validators = !config.import_all_attestations;
        let aggregate_validators_on_subnet =
            track_validators.then(|| HashSetDelay::new(slot_duration));
        AttestationService {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            subscriptions: HashMapDelay::new(default_sync_committee_duration),
            permanent_attestation_subscriptions,
            scheduled_subscriptions: HashSetDelay::default(),
            aggregate_validators_on_subnet,
            waker: None,
            discovery_disabled: config.disable_discovery,
            subscribe_all_subnets: config.subscribe_all_subnets,
            proposer_only: config.proposer_only,
            log,
        }
    }

    /// Return count of all currently subscribed subnets (long-lived **and** short-lived).
    #[cfg(test)]
    pub fn subscription_count(&self) -> usize {
        if self.subscribe_all_subnets {
            self.beacon_chain.spec.attestation_subnet_count as usize
        } else {
            let count = self.subscriptions.keys().collect::<HashSet<_>>().len();
            count
        }
    }

    /// Return count of all currently subscribed sync committee subnets.
    #[cfg(test)]
    pub fn sync_committee_subscription_count(&self) -> usize {
        use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
        if self.subscribe_all_subnets {
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        } else {
            self.subscriptions.len()
        }
    }

    /// Returns whether we are subscribed to a subnet for testing purposes.
    #[cfg(test)]
    pub(crate) fn is_subscribed(&self, subnet_id: &SubnetId) -> bool {
        self.subscriptions
            .contains_key(&Subnet::Attestation(subnet_id))
    }

    /// Processes a list of validator subscriptions.
    ///
    /// This is fundamentally called form the HTTP API when a validator requests duties from us
    /// This will:
    /// - Register new validators as being known.
    /// - Search for peers for required subnets.
    /// - Request subscriptions for subnets on specific slots when required.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(
        &mut self,
        subscriptions: impl Iterator<Item = Subscription>,
    ) -> Result<(), String> {
        // If the node is in a proposer-only state, we ignore all subnet subscriptions.
        if self.proposer_only {
            return Ok(());
        }

        // Maps each subnet_id subscription to it's highest slot
        let mut subnets_to_discover: HashMap<Subnet, Slot> = HashMap::new();

        // Registers the validator with the attestation service.
        for general_subscription in subscriptions {
            match general_subscription {
                Subscription::Attestation(subscription) => {
                    metrics::inc_counter(&metrics::SUBNET_SUBSCRIPTION_REQUESTS);

                    // Compute the subnet that is associated with this subscription
                    let subnet_id = match SubnetId::compute_subnet::<T::EthSpec>(
                        subscription.slot,
                        subscription.attestation_committee_index,
                        subscription.committee_count_at_slot,
                        &self.beacon_chain.spec,
                    ) {
                        Ok(subnet_id) => Subnet::Attestation(subnet_id),
                        Err(e) => {
                            warn!(self.log,
                                "Failed to compute subnet id for validator subscription";
                                "error" => ?e,
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
                        if let Err(e) = self.subscribe_to_subnet(exact_subnet) {
                            warn!(self.log,
                                "Subscription to subnet error";
                                "error" => e,
                            );
                        }
                    }
                }
                Subscription::SyncCommittee(subscription) => {
                    metrics::inc_counter(&metrics::SYNC_COMMITTEE_SUBSCRIPTION_REQUESTS);
                    // NOTE: We assume all subscriptions have been verified before reaching this service

                    // Registers the validator with the subnet service.
                    trace!(self.log,
                        "Sync committee subscription";
                        "subscription" => ?subscription,
                    );

                    let subnet_ids =
                        match SyncSubnetId::compute_subnets_for_sync_committee::<T::EthSpec>(
                            &subscription.sync_committee_indices,
                        ) {
                            Ok(subnet_ids) => subnet_ids,
                            Err(e) => {
                                warn!(self.log,
                                    "Failed to compute subnet id for sync committee subscription";
                                    "error" => ?e,
                                    "validator_index" => subscription.validator_index
                                );
                                continue;
                            }
                        };

                    for subnet_id in subnet_ids {
                        let exact_subnet = ExactSubnet {
                            subnet_id: Subnet::SyncCommittee(subnet_id),
                            slot: subscription
                                .until_epoch
                                .start_slot(T::EthSpec::slots_per_epoch()),
                        };
                        subnets_to_discover.push(exact_subnet.clone());
                        if let Err(e) = self.subscribe_to_sync_subnet(exact_subnet.subnet_id) {
                            warn!(self.log,
                                "Subscription to sync subnet error";
                                "error" => e,
                                "validator_index" => subscription.validator_index,
                            );
                        } else {
                            trace!(self.log,
                                "Subscribed to subnet for sync committee duties";
                                "exact_subnet" => ?exact_subnet,
                                "validator_index" => subscription.validator_index
                            );
                        }
                    }
                }
            }
        }

        // If the discovery mechanism isn't disabled, attempt to set up a peer discovery for the
        // required subnets.
        if !self.discovery_disabled {
            if let Err(e) = self.discover_peers_request(subnets_to_discover.into_iter()) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            };
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
        // Proposer-only mode does not need to process attestations
        if self.proposer_only {
            return false;
        }
        self.aggregate_validators_on_subnet
            .as_ref()
            .map(|tracked_vals| {
                tracked_vals.contains_key(&ExactSubnet {
                    subnet_id: subnet,
                    slot: attestation.data.slot,
                })
            })
            .unwrap_or(true)
    }

    /* Internal private functions */

    /// Adds an event to the event queue and notifies that this service is ready to be polled
    /// again.
    fn queue_event(&mut self, ev: SubnetServiceMessage) {
        self.events.push_back(ev);
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
    }
    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request.
    ///
    /// If there is sufficient time, queues a peer discovery request for all the required subnets.
    /// `subnets_to_discover` takes a (subnet_id, Option<Slot>), where if the slot is not set, we
    /// send a discovery request immediately.
    // NOTE: Sending early subscriptions results in early searching for peers on subnets.
    fn discover_peers_request(
        &mut self,
        subnets_to_discover: impl Iterator<Item = (Subnet, Slot)>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let discovery_subnets: Vec<SubnetDiscovery> = subnets_to_discover
            .filter_map(|(subnet, relevant_slot)| {
                // We generate discovery requests for all subnets (even one's we are permenantly
                // subscribed to) in order to ensure our peer counts are satisfactory to perform the
                // necessary duties.

                // Check if there is enough time to perform a discovery lookup.
                if relevant_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD)
                {
                    // Send out an event to start looking for peers.
                    // Require the peer for an additional slot to ensure we keep the peer for the
                    // duration of the subscription.
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(relevant_slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery { subnet, min_ttl })
                } else {
                    // We may want to check the global PeerInfo to see estimated timeouts for each
                    // peer before they can be removed.
                    warn!(self.log,
                        "Not enough time for a discovery search";
                        "subnet_id" => ?subnet,
                    );
                    None
                }
            })
            .collect();

        if !discovery_subnets.is_empty() {
            self.queue_event(SubnetServiceMessage::DiscoverPeers(discovery_subnets));
        }
        Ok(())
    }

    // Subscribes to the subnet if it should be done immediately, or schedules it if required.
    fn subscribe_to_subnet(
        &mut self,
        ExactSubnet { subnet_id, slot }: ExactSubnet,
    ) -> Result<(), &'static str> {
        // If the subnet is one of our permanent subnets, we do not need to subscribe.
        if self.subscribe_all_subnets
            || self
                .permanent_attestation_subscriptions
                .contains(&subnet_id)
        {
            return Ok(());
        }

        let slot_duration = self.beacon_chain.slot_clock.slot_duration();

        // Calculate how long before we need to subscribe to the subnet.
        let time_to_subscription_start = {
            // The short time we schedule the subscription before it's actually required. This
            // ensures we are subscribed on time, and allows consecutive subscriptions to the same
            // subnet to overlap, reducing subnet churn.
            let advance_subscription_duration = slot_duration / ADVANCE_SUBSCRIBE_SLOT_FRACTION;
            // The time to the required slot.
            let time_to_subscription_slot = self
                .beacon_chain
                .slot_clock
                .duration_to_slot(slot)
                .unwrap_or_default(); // If this is a past slot we will just get a 0 duration.
            time_to_subscription_slot.saturating_sub(advance_subscription_duration)
        };

        if let Some(tracked_vals) = self.aggregate_validators_on_subnet.as_mut() {
            tracked_vals.insert(ExactSubnet { subnet_id, slot });
        }

        // If the subscription should be done in the future, schedule it. Otherwise subscribe
        // immediately.
        if time_to_subscription_start.is_zero() {
            // This is a current or past slot, we subscribe immediately.
            self.subscribe_to_subnet_immediately(subnet_id, slot + 1)?;
        } else {
            // This is a future slot, schedule subscribing.
            trace!(self.log, "Scheduling subnet subscription"; "subnet" => ?subnet_id, "time_to_subscription_start" => ?time_to_subscription_start);
            self.scheduled_subscriptions
                .insert_at(ExactSubnet { subnet_id, slot }, time_to_subscription_start);
        }

        Ok(())
    }

    /// Adds a subscription event and an associated unsubscription event if required.
    fn subscribe_to_sync_subnet(&mut self, exact_subnet: ExactSubnet) -> Result<(), &'static str> {
        // Return if we have subscribed to all subnets
        if self.subscribe_all_subnets {
            return Ok(());
        }

        // Return if we already have a subscription for the subnet and its closer or
        if let Some(until_slot) = self.subscriptions.get(exact_subnet.subnet_id) {
            if until_slot >= *exact_subnet.slot {
                return Ok(());
            }
        }

        // Initialise timing variables
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        // Calculate the duration to the unsubscription event.
        let expected_end_subscription_duration = if current_slot >= exact_subnet.slot {
            warn!(
                self.log,
                "Sync committee subscription is past expiration";
                "current_slot" => current_slot,
                "exact_subnet" => ?exact_subnet,
            );
            return Ok(());
        } else {
            let slot_duration = self.beacon_chain.slot_clock.slot_duration();

            // the duration until we no longer need this subscription. We assume a single slot is
            // sufficient.
            self.beacon_chain
                .slot_clock
                .duration_to_slot(exact_subnet.slot)
                .ok_or("Unable to determine duration to unsubscription slot")?
                + slot_duration
        };

        if !self
            .subscriptions
            .insert_at(exact_subnet.subnet_id, expected_end_subscription_duration)
        {
            // We are not currently subscribed and have no waiting subscription, create one
            debug!(self.log, "Subscribing to subnet"; "subnet" => *exact_subnet.subnet_id, "until_epoch" => ?exact_subnet.slot);
            self.events
                .push_back(SubnetServiceMessage::Subscribe(Subnet::SyncCommittee(
                    exact_subnet.subnet_id,
                )));

            // add the subnet to the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrAdd(Subnet::SyncCommittee(
                    exact_subnet.subnet_id,
                )));
        }
        Ok(())
    }

    /* A collection of functions that handle the various timeouts */

    /// Registers a subnet as subscribed.
    ///
    /// Checks that the time in which the subscription would end is not in the past. If we are
    /// already subscribed, extends the timeout if necessary. If this is a new subscription, we send
    /// out the appropriate events.
    ///
    /// On determinist long lived subnets, this is only used for short lived subscriptions.
    fn subscribe_to_subnet_immediately(
        &mut self,
        subnet_id: SubnetId,
        end_slot: Slot,
    ) -> Result<(), &'static str> {
        if self.subscribe_all_subnets {
            // Case not handled by this service.
            return Ok(());
        }

        let time_to_subscription_end = self
            .beacon_chain
            .slot_clock
            .duration_to_slot(end_slot)
            .unwrap_or_default();

        // First check this is worth doing.
        if time_to_subscription_end.is_zero() {
            return Err("Time when subscription would end has already passed.");
        }

        // We need to check and add a subscription for the right kind, regardless of the presence
        // of the subnet as a subscription of the other kind. This is mainly since long lived
        // subscriptions can be removed at any time when a validator goes offline.

        match self.subscriptions.get(&subnet_id) {
            Some(current_end_slot) => {
                // We are already subscribed. Check if we need to extend the subscription.
                if &end_slot > current_end_slot {
                    trace!(self.log, "Extending subscription to subnet";
                        "subnet" => ?subnet_id,
                        "prev_end_slot" => current_end_slot,
                        "new_end_slot" => end_slot,
                    );
                    self.subscriptions
                        .insert_at(subnet_id, end_slot, time_to_subscription_end);
                }
            }
            None => {
                // This is a new subscription. Add with the corresponding timeout and send the
                // notification.
                self.subscriptions
                    .insert_at(subnet_id, end_slot, time_to_subscription_end);

                // Inform of the subscription.
                debug!(self.log, "Subscribing to subnet";
                    "subnet" => ?subnet_id,
                    "end_slot" => end_slot,
                );
                self.queue_event(SubnetServiceMessage::Subscribe(Subnet::Attestation(
                    subnet_id,
                )));
            }
        }

        Ok(())
    }

    // Unsubscribes from a subnet that was removed if it does not continue to exist as a
    // subscription of the other kind. For long lived subscriptions, it also removes the
    // advertisement from our ENR.
    fn handle_removed_subnet(&mut self, subnet_id: SubnetId) {
        if !self.subscriptions.contains_key(&subnet_id) {
            // Subscription no longer exists as short lived or long lived.
            debug!(self.log, "Unsubscribing from subnet"; "subnet" => ?subnet_id);
            self.queue_event(SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                subnet_id,
            )));
        }
    }
}

impl<T: BeaconChainTypes> Stream for AttestationService<T> {
    type Item = SubnetServiceMessage;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Update the waker if needed.
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        // Send out any generated events.
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        // Process scheduled subscriptions that might be ready, since those can extend a soon to
        // expire subscription.
        match self.scheduled_subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(ExactSubnet { subnet_id, slot }))) => {
                if let Err(e) = self.subscribe_to_subnet_immediately(subnet_id, slot + 1) {
                    debug!(self.log, "Failed to subscribe to short lived subnet"; "subnet" => ?subnet_id, "err" => e);
                }
                self.waker
                    .as_ref()
                    .expect("Waker has been set")
                    .wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for scheduled subnet subscriptions"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // Process any expired subscriptions.
        match self.subscriptions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((subnet_id, _end_slot)))) => {
                self.handle_removed_subnet(subnet_id);
                // We re-wake the task as there could be other subscriptions to process
                self.waker
                    .as_ref()
                    .expect("Waker has been set")
                    .wake_by_ref();
            }
            Poll::Ready(Some(Err(e))) => {
                error!(self.log, "Failed to check for subnet unsubscription times"; "error"=> e);
            }
            Poll::Ready(None) | Poll::Pending => {}
        }

        // Poll to remove entries on expiration, no need to act on expiration events.
        if let Some(tracked_vals) = self.aggregate_validators_on_subnet.as_mut() {
            if let Poll::Ready(Some(Err(e))) = tracked_vals.poll_next_unpin(cx) {
                error!(self.log, "Failed to check for aggregate validator on subnet expirations"; "error"=> e);
            }
        }

        Poll::Pending
    }
}

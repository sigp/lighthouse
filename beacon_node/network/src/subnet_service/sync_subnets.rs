//! This service keeps track of which sync committee subnet the beacon node should be subscribed to at any
//! given time. It schedules subscriptions to sync committee subnets and requests peer discoveries.

use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::prelude::*;
use slog::{debug, error, o, trace, warn};

use super::SubnetServiceMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{NetworkConfig, Subnet, SubnetDiscovery};
use hashset_delay::HashSetDelay;
use slot_clock::SlotClock;
use types::{Epoch, EthSpec, SyncCommitteeSubscription, SyncSubnetId};

use crate::metrics;

/// The minimum number of slots ahead that we attempt to discover peers for a subscription. If the
/// slot is less than this number, skip the peer discovery process.
/// Subnet discovery query takes atmost 30 secs, 2 slots take 24s.
const MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD: u64 = 2;

/// A particular subnet at a given slot.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct ExactSubnet {
    /// The `SyncSubnetId` associated with this subnet.
    pub subnet_id: SyncSubnetId,
    /// The epoch until which we need to stay subscribed to the subnet.
    pub until_epoch: Epoch,
}
pub struct SyncCommitteeService<T: BeaconChainTypes> {
    /// Queued events to return to the driving service.
    events: VecDeque<SubnetServiceMessage>,

    /// A reference to the beacon chain to process received attestations.
    pub(crate) beacon_chain: Arc<BeaconChain<T>>,

    /// The collection of all currently subscribed subnets.
    subscriptions: HashMap<SyncSubnetId, Epoch>,

    /// A collection of timeouts for when to unsubscribe from a subnet.
    unsubscriptions: HashSetDelay<SyncSubnetId>,

    /// The waker for the current thread.
    waker: Option<std::task::Waker>,

    /// The discovery mechanism of lighthouse is disabled.
    discovery_disabled: bool,

    /// We are always subscribed to all subnets.
    subscribe_all_subnets: bool,

    /// The logger for the attestation service.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> SyncCommitteeService<T> {
    /* Public functions */

    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        config: &NetworkConfig,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(o!("service" => "sync_committee_service"));

        let spec = &beacon_chain.spec;
        let epoch_duration_secs =
            beacon_chain.slot_clock.slot_duration().as_secs() * T::EthSpec::slots_per_epoch();
        let default_timeout =
            epoch_duration_secs.saturating_mul(spec.epochs_per_sync_committee_period.as_u64());

        SyncCommitteeService {
            events: VecDeque::with_capacity(10),
            beacon_chain,
            subscriptions: HashMap::new(),
            unsubscriptions: HashSetDelay::new(Duration::from_secs(default_timeout)),
            waker: None,
            subscribe_all_subnets: config.subscribe_all_subnets,
            discovery_disabled: config.disable_discovery,
            log,
        }
    }

    /// Return count of all currently subscribed subnets.
    #[cfg(test)]
    pub fn subscription_count(&self) -> usize {
        use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
        if self.subscribe_all_subnets {
            SYNC_COMMITTEE_SUBNET_COUNT as usize
        } else {
            self.subscriptions.len()
        }
    }

    /// Processes a list of sync committee subscriptions.
    ///
    /// This will:
    /// - Search for peers for required subnets.
    /// - Request subscriptions required subnets.
    /// - Build the timeouts for each of these events.
    ///
    /// This returns a result simply for the ergonomics of using ?. The result can be
    /// safely dropped.
    pub fn validator_subscriptions(
        &mut self,
        subscriptions: Vec<SyncCommitteeSubscription>,
    ) -> Result<(), String> {
        let mut subnets_to_discover = Vec::new();
        for subscription in subscriptions {
            metrics::inc_counter(&metrics::SYNC_COMMITTEE_SUBSCRIPTION_REQUESTS);
            //NOTE: We assume all subscriptions have been verified before reaching this service

            // Registers the validator with the subnet  service.
            // This will subscribe to long-lived random subnets if required.
            trace!(self.log,
                "Sync committee subscription";
                "subscription" => ?subscription,
            );

            let subnet_ids = match SyncSubnetId::compute_subnets_for_sync_committee::<T::EthSpec>(
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
                    subnet_id,
                    until_epoch: subscription.until_epoch,
                };
                subnets_to_discover.push(exact_subnet.clone());
                if let Err(e) = self.subscribe_to_subnet(exact_subnet.clone()) {
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
        // If the discovery mechanism isn't disabled, attempt to set up a peer discovery for the
        // required subnets.
        if !self.discovery_disabled {
            if let Err(e) = self.discover_peers_request(subnets_to_discover.iter()) {
                warn!(self.log, "Discovery lookup request error"; "error" => e);
            };
        }

        // pre-emptively wake the thread to check for new events
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
        Ok(())
    }

    /* Internal private functions */

    /// Checks if there are currently queued discovery requests and the time required to make the
    /// request.
    ///
    /// If there is sufficient time, queues a peer discovery request for all the required subnets.
    fn discover_peers_request<'a>(
        &mut self,
        exact_subnets: impl Iterator<Item = &'a ExactSubnet>,
    ) -> Result<(), &'static str> {
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();

        let discovery_subnets: Vec<SubnetDiscovery> = exact_subnets
            .filter_map(|exact_subnet| {
                let until_slot = exact_subnet.until_epoch.end_slot(slots_per_epoch);
                // check if there is enough time to perform a discovery lookup
                if until_slot >= current_slot.saturating_add(MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD) {
                    // if the slot is more than epoch away, add an event to start looking for peers
                    // add one slot to ensure we keep the peer for the subscription slot
                    let min_ttl = self
                        .beacon_chain
                        .slot_clock
                        .duration_to_slot(until_slot + 1)
                        .map(|duration| std::time::Instant::now() + duration);
                    Some(SubnetDiscovery {
                        subnet: Subnet::SyncCommittee(exact_subnet.subnet_id),
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

    /// Adds a subscription event and an associated unsubscription event if required.
    fn subscribe_to_subnet(&mut self, exact_subnet: ExactSubnet) -> Result<(), &'static str> {
        // Return if we have subscribed to all subnets
        if self.subscribe_all_subnets {
            return Ok(());
        }

        // Return if we already have a subscription for exact_subnet
        if self.subscriptions.get(&exact_subnet.subnet_id) == Some(&exact_subnet.until_epoch) {
            return Ok(());
        }

        // Return if we already have subscription set to expire later than the current request.
        if let Some(until_epoch) = self.subscriptions.get(&exact_subnet.subnet_id) {
            if *until_epoch >= exact_subnet.until_epoch {
                return Ok(());
            }
        }

        // initialise timing variables
        let current_slot = self
            .beacon_chain
            .slot_clock
            .now()
            .ok_or("Could not get the current slot")?;

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let until_slot = exact_subnet.until_epoch.end_slot(slots_per_epoch);
        // Calculate the duration to the unsubscription event.
        let expected_end_subscription_duration = if current_slot >= until_slot {
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
                .duration_to_slot(until_slot)
                .ok_or("Unable to determine duration to unsubscription slot")?
                + slot_duration
        };

        if let Entry::Vacant(e) = self.subscriptions.entry(exact_subnet.subnet_id) {
            // We are not currently subscribed and have no waiting subscription, create one
            debug!(self.log, "Subscribing to subnet"; "subnet" => *exact_subnet.subnet_id, "until_epoch" => ?exact_subnet.until_epoch);
            e.insert(exact_subnet.until_epoch);
            self.events
                .push_back(SubnetServiceMessage::Subscribe(Subnet::SyncCommittee(
                    exact_subnet.subnet_id,
                )));

            // add the subnet to the ENR bitfield
            self.events
                .push_back(SubnetServiceMessage::EnrAdd(Subnet::SyncCommittee(
                    exact_subnet.subnet_id,
                )));

            // add an unsubscription event to remove ourselves from the subnet once completed
            self.unsubscriptions
                .insert_at(exact_subnet.subnet_id, expected_end_subscription_duration);
        } else {
            // We are already subscribed, extend the unsubscription duration
            self.unsubscriptions
                .update_timeout(&exact_subnet.subnet_id, expected_end_subscription_duration);
        }

        Ok(())
    }

    /// A queued unsubscription is ready.
    fn handle_unsubscriptions(&mut self, subnet_id: SyncSubnetId) {
        debug!(self.log, "Unsubscribing from subnet"; "subnet" => *subnet_id);

        self.subscriptions.remove(&subnet_id);
        self.events
            .push_back(SubnetServiceMessage::Unsubscribe(Subnet::SyncCommittee(
                subnet_id,
            )));

        self.events
            .push_back(SubnetServiceMessage::EnrRemove(Subnet::SyncCommittee(
                subnet_id,
            )));
    }
}

impl<T: BeaconChainTypes> Stream for SyncCommitteeService<T> {
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

        // process any generated events
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Some(event));
        }

        Poll::Pending
    }
}

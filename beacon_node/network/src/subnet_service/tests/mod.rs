use super::*;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    BeaconChain,
};
use eth2_libp2p::NetworkConfig;
use futures::prelude::*;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use lazy_static::lazy_static;
use slog::Logger;
use sloggers::{null::NullLoggerBuilder, Build};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use store::config::StoreConfig;
use store::{HotColdDB, MemoryStore};
use types::{
    CommitteeIndex, Epoch, EthSpec, MainnetEthSpec, Slot, SubnetId, SyncCommitteeSubscription,
    SyncSubnetId, ValidatorSubscription,
};

const SLOT_DURATION_MILLIS: u64 = 400;

type TestBeaconChainType = Witness<
    SystemTimeSlotClock,
    CachingEth1Backend<MainnetEthSpec>,
    MainnetEthSpec,
    MemoryStore<MainnetEthSpec>,
    MemoryStore<MainnetEthSpec>,
>;

pub struct TestBeaconChain {
    chain: Arc<BeaconChain<TestBeaconChainType>>,
}

impl TestBeaconChain {
    pub fn new_with_system_clock() -> Self {
        let spec = MainnetEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(1);

        let log = get_logger();
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone(), log.clone()).unwrap();

        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);

        let chain = Arc::new(
            BeaconChainBuilder::new(MainnetEthSpec)
                .logger(log.clone())
                .custom_spec(spec.clone())
                .store(Arc::new(store))
                .genesis_state(
                    interop_genesis_state::<MainnetEthSpec>(&keypairs, 0, &spec)
                        .expect("should generate interop state"),
                )
                .expect("should build state using recent genesis")
                .dummy_eth1_backend()
                .expect("should build dummy backend")
                .slot_clock(SystemTimeSlotClock::new(
                    Slot::new(0),
                    Duration::from_secs(recent_genesis_time()),
                    Duration::from_millis(SLOT_DURATION_MILLIS),
                ))
                .shutdown_sender(shutdown_tx)
                .monitor_validators(true, vec![], log)
                .build()
                .expect("should build"),
        );
        Self { chain }
    }
}

pub fn recent_genesis_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_logger() -> Logger {
    NullLoggerBuilder.build().expect("logger should build")
}

lazy_static! {
    static ref CHAIN: TestBeaconChain = TestBeaconChain::new_with_system_clock();
}

fn get_attestation_service() -> AttestationService<TestBeaconChainType> {
    let log = get_logger();
    let config = NetworkConfig::default();

    let beacon_chain = CHAIN.chain.clone();

    AttestationService::new(beacon_chain, &config, &log)
}

fn get_sync_committee_service() -> SyncCommitteeService<TestBeaconChainType> {
    let log = get_logger();
    let config = NetworkConfig::default();

    let beacon_chain = CHAIN.chain.clone();

    SyncCommitteeService::new(beacon_chain, &config, &log)
}

// gets a number of events from the subscription service, or returns none if it times out after a number
// of slots
async fn get_events<S: Stream<Item = SubnetServiceMessage> + Unpin>(
    stream: &mut S,
    num_events: Option<usize>,
    num_slots_before_timeout: u32,
) -> Vec<SubnetServiceMessage> {
    let mut events = Vec::new();

    let collect_stream_fut = async {
        loop {
            if let Some(result) = stream.next().await {
                events.push(result);
                if let Some(num) = num_events {
                    if events.len() == num {
                        return;
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = collect_stream_fut => events,
        _ = tokio::time::sleep(
        Duration::from_millis(SLOT_DURATION_MILLIS) * num_slots_before_timeout,
    ) => events
    }
}

mod attestation_service {
    use super::*;

    fn get_subscription(
        validator_index: u64,
        attestation_committee_index: CommitteeIndex,
        slot: Slot,
        committee_count_at_slot: u64,
    ) -> ValidatorSubscription {
        let is_aggregator = true;
        ValidatorSubscription {
            validator_index,
            attestation_committee_index,
            slot,
            committee_count_at_slot,
            is_aggregator,
        }
    }

    fn get_subscriptions(
        validator_count: u64,
        slot: Slot,
        committee_count_at_slot: u64,
    ) -> Vec<ValidatorSubscription> {
        (0..validator_count)
            .map(|validator_index| {
                get_subscription(
                    validator_index,
                    validator_index,
                    slot,
                    committee_count_at_slot,
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn subscribe_current_slot_wait_for_unsubscribe() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        // Keep a low subscription slot so that there are no additional subnet discovery events.
        let subscription_slot = 0;
        let committee_count = 1;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = vec![get_subscription(
            validator_index,
            committee_index,
            current_slot + Slot::new(subscription_slot),
            committee_count,
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // not enough time for peer discovery, just subscribe, unsubscribe
        let subnet_id = SubnetId::compute_subnet::<MainnetEthSpec>(
            current_slot + Slot::new(subscription_slot),
            committee_index,
            committee_count,
            &attestation_service.beacon_chain.spec,
        )
        .unwrap();
        let expected = vec![
            SubnetServiceMessage::Subscribe(Subnet::Attestation(subnet_id)),
            SubnetServiceMessage::Unsubscribe(Subnet::Attestation(subnet_id)),
        ];

        // Wait for 1 slot duration to get the unsubscription event
        let events = get_events(
            &mut attestation_service,
            Some(5),
            (MainnetEthSpec::slots_per_epoch() * 3) as u32,
        )
        .await;
        matches::assert_matches!(
            events[..3],
            [
                SubnetServiceMessage::DiscoverPeers(_),
                SubnetServiceMessage::Subscribe(_any1),
                SubnetServiceMessage::EnrAdd(_any3)
            ]
        );

        // If the long lived and short lived subnets are the same, there should be no more events
        // as we don't resubscribe already subscribed subnets.
        if !attestation_service.random_subnets.contains(&subnet_id) {
            assert_eq!(expected[..], events[3..]);
        }
        // Should be subscribed to only 1 long lived subnet after unsubscription.
        assert_eq!(attestation_service.subscription_count(), 1);
    }

    /// Test to verify that we are not unsubscribing to a subnet before a required subscription.
    #[tokio::test]
    async fn test_same_subnet_unsubscription() {
        // subscription config
        let validator_index = 1;
        let committee_count = 1;

        // Makes 2 validator subscriptions to the same subnet but at different slots.
        // There should be just 1 unsubscription event for the later slot subscription (subscription_slot2).
        let subscription_slot1 = 0;
        let subscription_slot2 = 1;
        let com1 = 1;
        let com2 = 0;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let sub1 = get_subscription(
            validator_index,
            com1,
            current_slot + Slot::new(subscription_slot1),
            committee_count,
        );

        let sub2 = get_subscription(
            validator_index,
            com2,
            current_slot + Slot::new(subscription_slot2),
            committee_count,
        );

        let subnet_id1 = SubnetId::compute_subnet::<MainnetEthSpec>(
            current_slot + Slot::new(subscription_slot1),
            com1,
            committee_count,
            &attestation_service.beacon_chain.spec,
        )
        .unwrap();

        let subnet_id2 = SubnetId::compute_subnet::<MainnetEthSpec>(
            current_slot + Slot::new(subscription_slot2),
            com2,
            committee_count,
            &attestation_service.beacon_chain.spec,
        )
        .unwrap();

        // Assert that subscriptions are different but their subnet is the same
        assert_ne!(sub1, sub2);
        assert_eq!(subnet_id1, subnet_id2);

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(vec![sub1, sub2])
            .unwrap();

        // Unsubscription event should happen at slot 2 (since subnet id's are the same, unsubscription event should be at higher slot + 1)
        // Get all events for 1 slot duration (unsubscription event should happen after 2 slot durations).
        let events = get_events(&mut attestation_service, None, 1).await;
        matches::assert_matches!(
            events[..3],
            [
                SubnetServiceMessage::DiscoverPeers(_),
                SubnetServiceMessage::Subscribe(_any1),
                SubnetServiceMessage::EnrAdd(_any3)
            ]
        );

        let expected = SubnetServiceMessage::Subscribe(Subnet::Attestation(subnet_id1));

        // Should be still subscribed to 1 long lived and 1 short lived subnet if both are different.
        if !attestation_service.random_subnets.contains(&subnet_id1) {
            assert_eq!(expected, events[3]);
            assert_eq!(attestation_service.subscription_count(), 2);
        } else {
            assert_eq!(attestation_service.subscription_count(), 1);
        }

        // Get event for 1 more slot duration, we should get the unsubscribe event now.
        let unsubscribe_event = get_events(&mut attestation_service, None, 1).await;

        // If the long lived and short lived subnets are different, we should get an unsubscription event.
        if !attestation_service.random_subnets.contains(&subnet_id1) {
            assert_eq!(
                [SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                    subnet_id1
                ))],
                unsubscribe_event[..]
            );
        }

        // Should be subscribed to only 1 long lived subnet after unsubscription.
        assert_eq!(attestation_service.subscription_count(), 1);
    }

    #[tokio::test]
    async fn subscribe_all_random_subnets() {
        let attestation_subnet_count = MainnetEthSpec::default_spec().attestation_subnet_count;
        let subscription_slot = 10;
        let subscription_count = attestation_subnet_count;
        let committee_count = 1;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = get_subscriptions(
            subscription_count,
            current_slot + subscription_slot,
            committee_count,
        );

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let events = get_events(&mut attestation_service, None, 3).await;
        let mut discover_peer_count = 0;
        let mut enr_add_count = 0;
        let mut unexpected_msg_count = 0;

        for event in &events {
            match event {
                SubnetServiceMessage::DiscoverPeers(_) => discover_peer_count += 1,
                SubnetServiceMessage::Subscribe(_any_subnet) => {}
                SubnetServiceMessage::EnrAdd(_any_subnet) => enr_add_count += 1,
                _ => unexpected_msg_count += 1,
            }
        }

        // The bulk discovery request length should be equal to validator_count
        let bulk_discovery_event = events.last().unwrap();
        if let SubnetServiceMessage::DiscoverPeers(d) = bulk_discovery_event {
            assert_eq!(d.len(), attestation_subnet_count as usize);
        } else {
            panic!("Unexpected event {:?}", bulk_discovery_event);
        }

        // 64 `DiscoverPeer` requests of length 1 corresponding to random subnets
        // and 1 `DiscoverPeer` request corresponding to bulk subnet discovery.
        assert_eq!(discover_peer_count, subscription_count + 1);
        assert_eq!(attestation_service.subscription_count(), 64);
        assert_eq!(enr_add_count, 64);
        assert_eq!(unexpected_msg_count, 0);
        // test completed successfully
    }

    #[tokio::test]
    async fn subscribe_all_random_subnets_plus_one() {
        let attestation_subnet_count = MainnetEthSpec::default_spec().attestation_subnet_count;
        let subscription_slot = 10;
        // the 65th subscription should result in no more messages than the previous scenario
        let subscription_count = attestation_subnet_count + 1;
        let committee_count = 1;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = get_subscriptions(
            subscription_count,
            current_slot + subscription_slot,
            committee_count,
        );

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let events = get_events(&mut attestation_service, None, 3).await;
        let mut discover_peer_count = 0;
        let mut enr_add_count = 0;
        let mut unexpected_msg_count = 0;

        for event in &events {
            match event {
                SubnetServiceMessage::DiscoverPeers(_) => discover_peer_count += 1,
                SubnetServiceMessage::Subscribe(_any_subnet) => {}
                SubnetServiceMessage::EnrAdd(_any_subnet) => enr_add_count += 1,
                _ => unexpected_msg_count += 1,
            }
        }

        // The bulk discovery request length shouldn't exceed max attestation_subnet_count
        let bulk_discovery_event = events.last().unwrap();
        if let SubnetServiceMessage::DiscoverPeers(d) = bulk_discovery_event {
            assert_eq!(d.len(), attestation_subnet_count as usize);
        } else {
            panic!("Unexpected event {:?}", bulk_discovery_event);
        }
        // 64 `DiscoverPeer` requests of length 1 corresponding to random subnets
        // and 1 `DiscoverPeer` request corresponding to the bulk subnet discovery.
        // For the 65th subscription, the call to `subscribe_to_random_subnets` is not made because we are at capacity.
        assert_eq!(discover_peer_count, 64 + 1);
        assert_eq!(attestation_service.subscription_count(), 64);
        assert_eq!(enr_add_count, 64);
        assert_eq!(unexpected_msg_count, 0);
    }
}

mod sync_committee_service {
    use super::*;

    #[tokio::test]
    async fn subscribe_and_unsubscribe() {
        // subscription config
        let validator_index = 1;
        let until_epoch = Epoch::new(1);
        let sync_committee_indices = vec![1];

        // create the attestation service and subscriptions
        let mut sync_committee_service = get_sync_committee_service();

        let subscriptions = vec![SyncCommitteeSubscription {
            validator_index,
            sync_committee_indices: sync_committee_indices.clone(),
            until_epoch,
        }];

        // submit the subscriptions
        sync_committee_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let subnet_ids = SyncSubnetId::compute_subnets_for_sync_committee::<MainnetEthSpec>(
            &sync_committee_indices,
        )
        .unwrap();
        let subnet_id = subnet_ids.iter().next().unwrap();

        // Note: the unsubscription event takes 2 epochs (8 * 2 * 0.4 secs = 3.2 secs)
        let events = get_events(
            &mut sync_committee_service,
            Some(5),
            (MainnetEthSpec::slots_per_epoch() * 3) as u32, // Have some buffer time before getting 5 events
        )
        .await;
        assert_eq!(
            events[..2],
            [
                SubnetServiceMessage::Subscribe(Subnet::SyncCommittee(*subnet_id)),
                SubnetServiceMessage::EnrAdd(Subnet::SyncCommittee(*subnet_id))
            ]
        );
        matches::assert_matches!(
            events[2..],
            [
                SubnetServiceMessage::DiscoverPeers(_),
                SubnetServiceMessage::Unsubscribe(_),
                SubnetServiceMessage::EnrRemove(_),
            ]
        );

        // Should be unsubscribed at the end.
        assert_eq!(sync_committee_service.subscription_count(), 0);
    }

    #[tokio::test]
    async fn same_subscription_with_lower_until_epoch() {
        // subscription config
        let validator_index = 1;
        let until_epoch = Epoch::new(2);
        let sync_committee_indices = vec![1];

        // create the attestation service and subscriptions
        let mut sync_committee_service = get_sync_committee_service();

        let subscriptions = vec![SyncCommitteeSubscription {
            validator_index,
            sync_committee_indices: sync_committee_indices.clone(),
            until_epoch,
        }];

        // submit the subscriptions
        sync_committee_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // Get all immediate events (won't include unsubscriptions)
        let events = get_events(&mut sync_committee_service, None, 1).await;
        matches::assert_matches!(
            events[..],
            [
                SubnetServiceMessage::Subscribe(Subnet::SyncCommittee(_)),
                SubnetServiceMessage::EnrAdd(Subnet::SyncCommittee(_)),
                SubnetServiceMessage::DiscoverPeers(_),
            ]
        );

        // Additional subscriptions which shouldn't emit any non-discovery events
        // Event 1 is a duplicate of an existing subscription
        // Event 2 is the same subscription with lower `until_epoch` than the existing subscription
        let subscriptions = vec![
            SyncCommitteeSubscription {
                validator_index,
                sync_committee_indices: sync_committee_indices.clone(),
                until_epoch,
            },
            SyncCommitteeSubscription {
                validator_index,
                sync_committee_indices: sync_committee_indices.clone(),
                until_epoch: until_epoch - 1,
            },
        ];

        // submit the subscriptions
        sync_committee_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // Get all immediate events (won't include unsubscriptions)
        let events = get_events(&mut sync_committee_service, None, 1).await;
        matches::assert_matches!(events[..], [SubnetServiceMessage::DiscoverPeers(_),]);

        // Should be unsubscribed at the end.
        assert_eq!(sync_committee_service.subscription_count(), 1);
    }
}

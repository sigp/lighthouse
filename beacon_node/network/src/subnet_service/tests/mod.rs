use super::*;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    BeaconChain,
};
use futures::prelude::*;
use genesis::{generate_deterministic_keypairs, interop_genesis_state, DEFAULT_ETH1_BLOCK_HASH};
use lazy_static::lazy_static;
use lighthouse_network::NetworkConfig;
use slog::{o, Drain, Logger};
use sloggers::{null::NullLoggerBuilder, Build};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use store::config::StoreConfig;
use store::{HotColdDB, MemoryStore};
use task_executor::test_utils::TestRuntime;
use types::{
    CommitteeIndex, Epoch, EthSpec, Hash256, MainnetEthSpec, Slot, SubnetId,
    SyncCommitteeSubscription, SyncSubnetId, ValidatorSubscription,
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
    _test_runtime: TestRuntime,
}

impl TestBeaconChain {
    pub fn new_with_system_clock() -> Self {
        let spec = MainnetEthSpec::default_spec();

        let keypairs = generate_deterministic_keypairs(1);

        let log = get_logger(None);
        let store =
            HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone(), log.clone()).unwrap();

        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);

        let test_runtime = TestRuntime::default();

        let chain = Arc::new(
            BeaconChainBuilder::new(MainnetEthSpec)
                .logger(log.clone())
                .custom_spec(spec.clone())
                .store(Arc::new(store))
                .task_executor(test_runtime.task_executor.clone())
                .genesis_state(
                    interop_genesis_state::<MainnetEthSpec>(
                        &keypairs,
                        0,
                        Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
                        None,
                        &spec,
                    )
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
                .build()
                .expect("should build"),
        );
        Self {
            chain,
            _test_runtime: test_runtime,
        }
    }
}

pub fn recent_genesis_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn get_logger(log_level: Option<slog::Level>) -> Logger {
    if let Some(level) = log_level {
        let drain = {
            let decorator = slog_term::TermDecorator::new().build();
            let decorator =
                logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).chan_size(2048).build();
            drain.filter_level(level)
        };

        Logger::root(drain.fuse(), o!())
    } else {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }
}

lazy_static! {
    static ref CHAIN: TestBeaconChain = TestBeaconChain::new_with_system_clock();
}

fn get_attestation_service(
    log_level: Option<slog::Level>,
) -> AttestationService<TestBeaconChainType> {
    let log = get_logger(log_level);
    let config = NetworkConfig::default();

    let beacon_chain = CHAIN.chain.clone();

    AttestationService::new(
        beacon_chain,
        lighthouse_network::discv5::enr::NodeId::random(),
        &config,
        &log,
    )
}

fn get_sync_committee_service() -> SyncCommitteeService<TestBeaconChainType> {
    let log = get_logger(None);
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

    let timeout =
        tokio::time::sleep(Duration::from_millis(SLOT_DURATION_MILLIS) * num_slots_before_timeout);
    futures::pin_mut!(timeout);

    loop {
        tokio::select! {
            Some(event) = stream.next() => {
                events.push(event);
                if let Some(num) = num_events {
                    if events.len() == num {
                        break;
                    }
                }
            }
            _ = timeout.as_mut() => {
                break;
            }

        }
    }

    events
}

mod attestation_service {

    #[cfg(not(windows))]
    use crate::subnet_service::attestation_subnets::MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD;

    use super::*;

    fn get_subscription(
        validator_index: u64,
        attestation_committee_index: CommitteeIndex,
        slot: Slot,
        committee_count_at_slot: u64,
        is_aggregator: bool,
    ) -> ValidatorSubscription {
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
        is_aggregator: bool,
    ) -> Vec<ValidatorSubscription> {
        (0..validator_count)
            .map(|validator_index| {
                get_subscription(
                    validator_index,
                    validator_index,
                    slot,
                    committee_count_at_slot,
                    is_aggregator,
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
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(None);
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
            true,
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
            Some(subnets_per_node * 3 + 2),
            (MainnetEthSpec::slots_per_epoch() * 3) as u32,
        )
        .await;
        matches::assert_matches!(
            events[..6],
            [
                SubnetServiceMessage::Subscribe(_any1),
                SubnetServiceMessage::EnrAdd(_any3),
                SubnetServiceMessage::DiscoverPeers(_),
                SubnetServiceMessage::Subscribe(_),
                SubnetServiceMessage::EnrAdd(_),
                SubnetServiceMessage::DiscoverPeers(_),
            ]
        );

        // If the long lived and short lived subnets are the same, there should be no more events
        // as we don't resubscribe already subscribed subnets.
        if !attestation_service
            .is_subscribed(&subnet_id, attestation_subnets::SubscriptionKind::LongLived)
        {
            assert_eq!(expected[..], events[subnets_per_node * 3..]);
        }
        // Should be subscribed to only subnets_per_node long lived subnet after unsubscription.
        assert_eq!(attestation_service.subscription_count(), subnets_per_node);
    }

    /// Test to verify that we are not unsubscribing to a subnet before a required subscription.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn test_same_subnet_unsubscription() {
        // subscription config
        let validator_index = 1;
        let committee_count = 1;
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        // Makes 2 validator subscriptions to the same subnet but at different slots.
        // There should be just 1 unsubscription event for the later slot subscription (subscription_slot2).
        let subscription_slot1 = 0;
        let subscription_slot2 = 1;
        let com1 = 1;
        let com2 = 0;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(None);
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
            true,
        );

        let sub2 = get_subscription(
            validator_index,
            com2,
            current_slot + Slot::new(subscription_slot2),
            committee_count,
            true,
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
                SubnetServiceMessage::Subscribe(_any1),
                SubnetServiceMessage::EnrAdd(_any3),
                SubnetServiceMessage::DiscoverPeers(_),
            ]
        );

        let expected = SubnetServiceMessage::Subscribe(Subnet::Attestation(subnet_id1));

        // Should be still subscribed to 2 long lived and up to 1 short lived subnet if both are
        // different.
        if !attestation_service.is_subscribed(
            &subnet_id1,
            attestation_subnets::SubscriptionKind::LongLived,
        ) {
            // The index is 3*subnets_per_node (because we subscribe + discover + enr per long lived
            // subnet) + 1
            let index = 3 * subnets_per_node;
            assert_eq!(expected, events[index]);
            assert_eq!(
                attestation_service.subscription_count(),
                subnets_per_node + 1
            );
        } else {
            assert!(attestation_service.subscription_count() == subnets_per_node);
        }

        // Get event for 1 more slot duration, we should get the unsubscribe event now.
        let unsubscribe_event = get_events(&mut attestation_service, None, 1).await;

        // If the long lived and short lived subnets are different, we should get an unsubscription
        // event.
        if !attestation_service.is_subscribed(
            &subnet_id1,
            attestation_subnets::SubscriptionKind::LongLived,
        ) {
            assert_eq!(
                [SubnetServiceMessage::Unsubscribe(Subnet::Attestation(
                    subnet_id1
                ))],
                unsubscribe_event[..]
            );
        }

        // Should be subscribed 2 long lived subnet after unsubscription.
        assert_eq!(attestation_service.subscription_count(), subnets_per_node);
    }

    #[tokio::test]
    async fn subscribe_all_subnets() {
        let attestation_subnet_count = MainnetEthSpec::default_spec().attestation_subnet_count;
        let subscription_slot = 3;
        let subscription_count = attestation_subnet_count;
        let committee_count = 1;
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(None);
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = get_subscriptions(
            subscription_count,
            current_slot + subscription_slot,
            committee_count,
            true,
        );

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let events = get_events(&mut attestation_service, Some(131), 10).await;
        let mut discover_peer_count = 0;
        let mut enr_add_count = 0;
        let mut unexpected_msg_count = 0;
        let mut unsubscribe_event_count = 0;

        for event in &events {
            match event {
                SubnetServiceMessage::DiscoverPeers(_) => discover_peer_count += 1,
                SubnetServiceMessage::Subscribe(_any_subnet) => {}
                SubnetServiceMessage::EnrAdd(_any_subnet) => enr_add_count += 1,
                SubnetServiceMessage::Unsubscribe(_) => unsubscribe_event_count += 1,
                _ => unexpected_msg_count += 1,
            }
        }

        // There should be a Subscribe Event, and Enr Add event and a DiscoverPeers event for each
        // long-lived subnet initially. The next event should be a bulk discovery event.
        let bulk_discovery_index = 3 * subnets_per_node;
        // The bulk discovery request length should be equal to validator_count
        let bulk_discovery_event = &events[bulk_discovery_index];
        if let SubnetServiceMessage::DiscoverPeers(d) = bulk_discovery_event {
            assert_eq!(d.len(), attestation_subnet_count as usize);
        } else {
            panic!("Unexpected event {:?}", bulk_discovery_event);
        }

        // 64 `DiscoverPeer` requests of length 1 corresponding to deterministic subnets
        // and 1 `DiscoverPeer` request corresponding to bulk subnet discovery.
        assert_eq!(discover_peer_count, subnets_per_node + 1);
        assert_eq!(attestation_service.subscription_count(), subnets_per_node);
        assert_eq!(enr_add_count, subnets_per_node);
        assert_eq!(
            unsubscribe_event_count,
            attestation_subnet_count - subnets_per_node as u64
        );
        assert_eq!(unexpected_msg_count, 0);
        // test completed successfully
    }

    #[tokio::test]
    async fn subscribe_correct_number_of_subnets() {
        let attestation_subnet_count = MainnetEthSpec::default_spec().attestation_subnet_count;
        let subscription_slot = 10;
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        // the 65th subscription should result in no more messages than the previous scenario
        let subscription_count = attestation_subnet_count + 1;
        let committee_count = 1;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(None);
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = get_subscriptions(
            subscription_count,
            current_slot + subscription_slot,
            committee_count,
            true,
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
        // subnets_per_node `DiscoverPeer` requests of length 1 corresponding to long-lived subnets
        // and 1 `DiscoverPeer` request corresponding to the bulk subnet discovery.

        assert_eq!(discover_peer_count, subnets_per_node + 1);
        assert_eq!(attestation_service.subscription_count(), subnets_per_node);
        assert_eq!(enr_add_count, subnets_per_node);
        assert_eq!(unexpected_msg_count, 0);
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn test_subscribe_same_subnet_several_slots_apart() {
        // subscription config
        let validator_index = 1;
        let committee_count = 1;
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        // Makes 2 validator subscriptions to the same subnet but at different slots.
        // There should be just 1 unsubscription event for the later slot subscription (subscription_slot2).
        let subscription_slot1 = 0;
        let subscription_slot2 = MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD + 4;
        let com1 = MIN_PEER_DISCOVERY_SLOT_LOOK_AHEAD + 4;
        let com2 = 0;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service(None);
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
            true,
        );

        let sub2 = get_subscription(
            validator_index,
            com2,
            current_slot + Slot::new(subscription_slot2),
            committee_count,
            true,
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

        // Unsubscription event should happen at the end of the slot.
        let events = get_events(&mut attestation_service, None, 1).await;
        matches::assert_matches!(
            events[..3],
            [
                SubnetServiceMessage::Subscribe(_any1),
                SubnetServiceMessage::EnrAdd(_any3),
                SubnetServiceMessage::DiscoverPeers(_),
            ]
        );

        let expected_subscription =
            SubnetServiceMessage::Subscribe(Subnet::Attestation(subnet_id1));
        let expected_unsubscription =
            SubnetServiceMessage::Unsubscribe(Subnet::Attestation(subnet_id1));

        if !attestation_service.is_subscribed(
            &subnet_id1,
            attestation_subnets::SubscriptionKind::LongLived,
        ) {
            assert_eq!(expected_subscription, events[subnets_per_node * 3]);
            assert_eq!(expected_unsubscription, events[subnets_per_node * 3 + 2]);
        }
        assert_eq!(attestation_service.subscription_count(), 2);

        println!("{events:?}");
        let subscription_slot = current_slot + subscription_slot2 - 1; // one less do to the
                                                                       // advance subscription time
        let wait_slots = attestation_service
            .beacon_chain
            .slot_clock
            .duration_to_slot(subscription_slot)
            .unwrap()
            .as_millis() as u64
            / SLOT_DURATION_MILLIS;

        let no_events = dbg!(get_events(&mut attestation_service, None, wait_slots as u32).await);

        assert_eq!(no_events, []);

        let second_subscribe_event = get_events(&mut attestation_service, None, 2).await;
        // If the long lived and short lived subnets are different, we should get an unsubscription event.
        if !attestation_service.is_subscribed(
            &subnet_id1,
            attestation_subnets::SubscriptionKind::LongLived,
        ) {
            assert_eq!(
                [SubnetServiceMessage::Subscribe(Subnet::Attestation(
                    subnet_id1
                ))],
                second_subscribe_event[..]
            );
        }
    }

    #[tokio::test]
    async fn test_update_deterministic_long_lived_subnets() {
        let mut attestation_service = get_attestation_service(None);
        let subnets_per_node = MainnetEthSpec::default_spec().subnets_per_node as usize;

        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions = get_subscriptions(20, current_slot, 30, false);

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // There should only be the same subscriptions as there are in the specification,
        // regardless of subscriptions
        assert_eq!(
            attestation_service.long_lived_subscriptions().len(),
            subnets_per_node
        );

        let events = get_events(&mut attestation_service, None, 4).await;

        // Check that we attempt to subscribe and register ENRs
        matches::assert_matches!(
            events[..6],
            [
                SubnetServiceMessage::Subscribe(_),
                SubnetServiceMessage::EnrAdd(_),
                SubnetServiceMessage::DiscoverPeers(_),
                SubnetServiceMessage::Subscribe(_),
                SubnetServiceMessage::EnrAdd(_),
                SubnetServiceMessage::DiscoverPeers(_),
            ]
        );
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

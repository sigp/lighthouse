#[cfg(test)]
mod tests {
    use super::super::*;
    use beacon_chain::{
        builder::{BeaconChainBuilder, Witness},
        eth1_chain::CachingEth1Backend,
        events::NullEventHandler,
        migrate::NullMigrator,
    };
    use futures::Stream;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use lazy_static::lazy_static;
    use matches::assert_matches;
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use slot_clock::{SlotClock, SystemTimeSlotClock};
    use std::time::{Duration, SystemTime};
    use store::config::StoreConfig;
    use store::{HotColdDB, MemoryStore};
    use tempfile::tempdir;
    use types::{CommitteeIndex, EthSpec, MinimalEthSpec};

    const SLOT_DURATION_MILLIS: u64 = 200;

    type TestBeaconChainType = Witness<
        NullMigrator,
        SystemTimeSlotClock,
        CachingEth1Backend<MinimalEthSpec>,
        MinimalEthSpec,
        NullEventHandler<MinimalEthSpec>,
        MemoryStore<MinimalEthSpec>,
        MemoryStore<MinimalEthSpec>,
    >;

    pub struct TestBeaconChain {
        chain: Arc<BeaconChain<TestBeaconChainType>>,
    }

    impl TestBeaconChain {
        pub fn new_with_system_clock() -> Self {
            let data_dir = tempdir().expect("should create temporary data_dir");
            let spec = MinimalEthSpec::default_spec();

            let keypairs = generate_deterministic_keypairs(1);

            let log = get_logger();
            let store =
                HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone(), log.clone())
                    .unwrap();
            let chain = Arc::new(
                BeaconChainBuilder::new(MinimalEthSpec)
                    .logger(log.clone())
                    .custom_spec(spec.clone())
                    .store(Arc::new(store))
                    .store_migrator(NullMigrator)
                    .data_dir(data_dir.path().to_path_buf())
                    .genesis_state(
                        interop_genesis_state::<MinimalEthSpec>(&keypairs, 0, &spec)
                            .expect("should generate interop state"),
                    )
                    .expect("should build state using recent genesis")
                    .dummy_eth1_backend()
                    .expect("should build dummy backend")
                    .null_event_handler()
                    .slot_clock(SystemTimeSlotClock::new(
                        Slot::new(0),
                        Duration::from_secs(recent_genesis_time()),
                        Duration::from_millis(SLOT_DURATION_MILLIS),
                    ))
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

        let beacon_chain = CHAIN.chain.clone();

        AttestationService::new(beacon_chain, &log)
    }

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

    // gets a number of events from the subscription service, or returns none if it times out after a number
    // of slots
    async fn get_events<S: Stream<Item = AttServiceMessage> + Unpin>(
        stream: &mut S,
        num_events: Option<usize>,
        num_slots_before_timeout: u32,
    ) -> Vec<AttServiceMessage> {
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
            _ = collect_stream_fut => {return events}
            _ = tokio::time::delay_for(
            Duration::from_millis(SLOT_DURATION_MILLIS) * num_slots_before_timeout,
        ) => { return events; }
            }
    }

    #[tokio::test]
    async fn subscribe_current_slot() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 0;
        let num_events_expected = 4;
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

        // not enough time for peer discovery, just subscribe
        let expected = vec![AttServiceMessage::Subscribe(
            SubnetId::compute_subnet::<MinimalEthSpec>(
                current_slot + Slot::new(subscription_slot),
                committee_index,
                committee_count,
                &attestation_service.beacon_chain.spec,
            )
            .unwrap(),
        )];

        let events = get_events(&mut attestation_service, Some(num_events_expected), 1).await;
        assert_matches!(
            events[..3],
            [AttServiceMessage::DiscoverPeers(_), AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any3)]
        );

        // Should be subscribed to 1 long lived and one short lived subnet.
        assert_eq!(attestation_service.subscription_count(), 2);
        // if there are fewer events than expected, there's been a collision
        if events.len() == num_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_current_slot_wait_for_unsubscribe() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 0;
        let num_events_expected = 5;
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
        let subnet_id = SubnetId::compute_subnet::<MinimalEthSpec>(
            current_slot + Slot::new(subscription_slot),
            committee_index,
            committee_count,
            &attestation_service.beacon_chain.spec,
        )
        .unwrap();
        let expected = vec![
            AttServiceMessage::Subscribe(subnet_id),
            AttServiceMessage::Unsubscribe(subnet_id),
        ];

        let events = get_events(&mut attestation_service, Some(num_events_expected), 2).await;
        assert_matches!(
            events[..3],
            [AttServiceMessage::DiscoverPeers(_), AttServiceMessage::Subscribe(_any1), AttServiceMessage::EnrAdd(_any3)]
        );

        // Should be subscribed to only 1 long lived subnet after unsubscription.
        assert_eq!(attestation_service.subscription_count(), 1);
        // if there are fewer events than expected, there's been a collision
        if events.len() == num_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_all_random_subnets() {
        let attestation_subnet_count = MinimalEthSpec::default_spec().attestation_subnet_count;
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
                AttServiceMessage::DiscoverPeers(_) => {
                    discover_peer_count = discover_peer_count + 1
                }
                AttServiceMessage::Subscribe(_any_subnet) => {}
                AttServiceMessage::EnrAdd(_any_subnet) => enr_add_count = enr_add_count + 1,
                _ => unexpected_msg_count = unexpected_msg_count + 1,
            }
        }

        // The bulk discovery request length should be equal to validator_count
        let bulk_discovery_event = events.last().unwrap();
        if let AttServiceMessage::DiscoverPeers(d) = bulk_discovery_event {
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
        let attestation_subnet_count = MinimalEthSpec::default_spec().attestation_subnet_count;
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
                AttServiceMessage::DiscoverPeers(_) => {
                    discover_peer_count = discover_peer_count + 1
                }
                AttServiceMessage::Subscribe(_any_subnet) => {}
                AttServiceMessage::EnrAdd(_any_subnet) => enr_add_count = enr_add_count + 1,
                _ => unexpected_msg_count = unexpected_msg_count + 1,
            }
        }

        // The bulk discovery request length shouldn't exceed max attestation_subnet_count
        let bulk_discovery_event = events.last().unwrap();
        if let AttServiceMessage::DiscoverPeers(d) = bulk_discovery_event {
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

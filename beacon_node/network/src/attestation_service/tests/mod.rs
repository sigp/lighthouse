#[cfg(test)]
mod tests {
    use super::super::*;
    use beacon_chain::{
        builder::{BeaconChainBuilder, Witness},
        eth1_chain::CachingEth1Backend,
        events::NullEventHandler,
        migrate::NullMigrator,
    };
    use eth2_libp2p::discovery::{build_enr, Keypair};
    use eth2_libp2p::{discovery::CombinedKey, CombinedKeyExt, NetworkConfig, NetworkGlobals};
    use futures::Stream;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use lazy_static::lazy_static;
    use matches::assert_matches;
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use slot_clock::{SlotClock, SystemTimeSlotClock};
    use std::time::{Duration, SystemTime};
    use store::MemoryStore;
    use tempfile::tempdir;
    use types::{CommitteeIndex, EnrForkId, EthSpec, MinimalEthSpec};

    const SLOT_DURATION_MILLIS: u64 = 200;

    type TestBeaconChainType = Witness<
        MemoryStore<MinimalEthSpec>,
        NullMigrator,
        SystemTimeSlotClock,
        CachingEth1Backend<MinimalEthSpec, MemoryStore<MinimalEthSpec>>,
        MinimalEthSpec,
        NullEventHandler<MinimalEthSpec>,
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
            let chain = Arc::new(
                BeaconChainBuilder::new(MinimalEthSpec)
                    .logger(log.clone())
                    .custom_spec(spec.clone())
                    .store(Arc::new(MemoryStore::open()))
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
                    .reduced_tree_fork_choice()
                    .expect("should add fork choice to builder")
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
        static ref CHAIN: TestBeaconChain = { TestBeaconChain::new_with_system_clock() };
    }

    fn get_attestation_service() -> AttestationService<TestBeaconChainType> {
        let log = get_logger();

        let beacon_chain = CHAIN.chain.clone();

        let config = NetworkConfig::default();
        let enr_key = CombinedKey::from_libp2p(&Keypair::generate_secp256k1()).unwrap();
        let enr = build_enr::<MinimalEthSpec>(&enr_key, &config, EnrForkId::default()).unwrap();

        let network_globals: NetworkGlobals<MinimalEthSpec> = NetworkGlobals::new(enr, 0, 0, &log);
        AttestationService::new(beacon_chain, Arc::new(network_globals), &log)
    }

    fn get_subscription(
        validator_index: u64,
        attestation_committee_index: CommitteeIndex,
        slot: Slot,
    ) -> ValidatorSubscription {
        let is_aggregator = true;
        ValidatorSubscription {
            validator_index,
            attestation_committee_index,
            slot,
            is_aggregator,
        }
    }

    fn _get_subscriptions(validator_count: u64, slot: Slot) -> Vec<ValidatorSubscription> {
        let mut subscriptions: Vec<ValidatorSubscription> = Vec::new();
        for validator_index in 0..validator_count {
            let is_aggregator = true;
            subscriptions.push(ValidatorSubscription {
                validator_index,
                attestation_committee_index: validator_index,
                slot,
                is_aggregator,
            });
        }
        subscriptions
    }

    // gets a number of events from the subscription service, or returns none if it times out after a number
    // of slots
    async fn get_events<S: Stream<Item = AttServiceMessage> + Unpin>(
        mut stream: S,
        no_events: usize,
        no_slots_before_timeout: u32,
    ) -> Vec<AttServiceMessage> {
        let mut events = Vec::new();

        let collect_stream_fut = async {
            loop {
                if let Some(result) = stream.next().await {
                    events.push(result);
                    if events.len() == no_events {
                        return;
                    }
                }
            }
        };

        tokio::select! {
            _ = collect_stream_fut => {return events}
            _ = tokio::time::delay_for(
            Duration::from_millis(SLOT_DURATION_MILLIS) * no_slots_before_timeout,
        ) => { return events; }
            }
    }

    #[tokio::test]
    async fn subscribe_current_slot() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 0;
        let no_events_expected = 4;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // not enough time for peer discovery, just subscribe
        let expected = vec![AttServiceMessage::Subscribe(SubnetId::new(validator_index))];

        let events = get_events(attestation_service, no_events_expected, 1).await;
        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any1),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_current_slot_wait_for_unsubscribe() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 0;
        let no_events_expected = 5;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // not enough time for peer discovery, just subscribe, unsubscribe
        let expected = vec![
            AttServiceMessage::Subscribe(SubnetId::new(validator_index)),
            AttServiceMessage::Unsubscribe(SubnetId::new(validator_index)),
        ];

        let events = get_events(attestation_service, no_events_expected, 2).await;
        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any1),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_five_slots_ahead() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 5;
        let no_events_expected = 4;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let min_ttl = Instant::now().checked_add(
            attestation_service
                .beacon_chain
                .slot_clock
                .duration_to_slot(current_slot + Slot::new(subscription_slot) + Slot::new(1))
                .unwrap(),
        );

        // just discover peers, don't subscribe yet
        let expected = vec![AttServiceMessage::DiscoverPeers {
            subnet_id: SubnetId::new(validator_index),
            min_ttl,
        }];

        let events = get_events(attestation_service, no_events_expected, 1).await;
        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any2),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_five_slots_ahead_wait_five_slots() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 5;
        let no_events_expected = 5;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let min_ttl = Instant::now().checked_add(
            attestation_service
                .beacon_chain
                .slot_clock
                .duration_to_slot(current_slot + Slot::new(subscription_slot) + Slot::new(1))
                .unwrap(),
        );

        // we should discover peers, wait, then subscribe
        let expected = vec![
            AttServiceMessage::DiscoverPeers {
                subnet_id: SubnetId::new(validator_index),
                min_ttl,
            },
            AttServiceMessage::Subscribe(SubnetId::new(validator_index)),
        ];

        let events = get_events(attestation_service, no_events_expected, 5).await;
        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any2),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_7_slots_ahead() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 7;
        let no_events_expected = 3;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        // ten slots ahead is before our target peer discover time, so expect no messages
        let expected: Vec<AttServiceMessage> = vec![];

        let events = get_events(attestation_service, no_events_expected, 1).await;

        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any2),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_ten_slots_ahead_wait_five_slots() {
        // subscription config
        let validator_index = 1;
        let committee_index = 1;
        let subscription_slot = 10;
        let no_events_expected = 4;

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
        )];

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let min_ttl = Instant::now().checked_add(
            attestation_service
                .beacon_chain
                .slot_clock
                .duration_to_slot(current_slot + Slot::new(subscription_slot) + Slot::new(1))
                .unwrap(),
        );

        // expect discover peers because we will enter TARGET_PEER_DISCOVERY_SLOT_LOOK_AHEAD range
        let expected: Vec<AttServiceMessage> = vec![AttServiceMessage::DiscoverPeers {
            subnet_id: SubnetId::new(validator_index),
            min_ttl,
        }];

        let events = get_events(attestation_service, no_events_expected, 5).await;

        assert_matches!(
            events[..3],
            [
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant
                },
                AttServiceMessage::Subscribe(_any2),
                AttServiceMessage::EnrAdd(_any3)
            ]
        );
        // if there are fewer events than expected, there's been a collision
        if events.len() == no_events_expected {
            assert_eq!(expected[..], events[3..]);
        }
    }

    #[tokio::test]
    async fn subscribe_all_random_subnets() {
        // subscribe 10 slots ahead so we do not produce any exact subnet messages
        let subscription_slot = 10;
        let subscription_count = 64;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions =
            _get_subscriptions(subscription_count, current_slot + subscription_slot);

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let events = get_events(attestation_service, 192, 3).await;
        let mut discover_peer_count = 0;
        let mut subscribe_count = 0;
        let mut enr_add_count = 0;
        let mut unexpected_msg_count = 0;

        for event in events {
            match event {
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant,
                } => discover_peer_count = discover_peer_count + 1,
                AttServiceMessage::Subscribe(_any_subnet) => subscribe_count = subscribe_count + 1,
                AttServiceMessage::EnrAdd(_any_subnet) => enr_add_count = enr_add_count + 1,
                _ => unexpected_msg_count = unexpected_msg_count + 1,
            }
        }

        assert_eq!(discover_peer_count, 64);
        assert_eq!(subscribe_count, 64);
        assert_eq!(enr_add_count, 64);
        assert_eq!(unexpected_msg_count, 0);
        // test completed successfully
    }

    #[tokio::test]
    async fn subscribe_all_random_subnets_plus_one() {
        // subscribe 10 slots ahead so we do not produce any exact subnet messages
        let subscription_slot = 10;
        // the 65th subscription should result in no more messages than the previous scenario
        let subscription_count = 65;

        // create the attestation service and subscriptions
        let mut attestation_service = get_attestation_service();
        let current_slot = attestation_service
            .beacon_chain
            .slot_clock
            .now()
            .expect("Could not get current slot");

        let subscriptions =
            _get_subscriptions(subscription_count, current_slot + subscription_slot);

        // submit the subscriptions
        attestation_service
            .validator_subscriptions(subscriptions)
            .unwrap();

        let events = get_events(attestation_service, 192, 3).await;
        let mut discover_peer_count = 0;
        let mut subscribe_count = 0;
        let mut enr_add_count = 0;
        let mut unexpected_msg_count = 0;

        for event in events {
            match event {
                AttServiceMessage::DiscoverPeers {
                    subnet_id: _any_subnet,
                    min_ttl: _any_instant,
                } => discover_peer_count = discover_peer_count + 1,
                AttServiceMessage::Subscribe(_any_subnet) => subscribe_count = subscribe_count + 1,
                AttServiceMessage::EnrAdd(_any_subnet) => enr_add_count = enr_add_count + 1,
                _ => unexpected_msg_count = unexpected_msg_count + 1,
            }
        }

        assert_eq!(discover_peer_count, 64);
        assert_eq!(subscribe_count, 64);
        assert_eq!(enr_add_count, 64);
        assert_eq!(unexpected_msg_count, 0);
    }
}

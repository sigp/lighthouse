use crate::duties_service::DutiesService;
use beacon_node_fallback::BeaconNodeFallback;
use eth2::types::{InclusionListDuty, InclusionListTransactions};
use logging::crit;
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use tracing::{debug, error, info};
use types::{ChainSpec, EthSpec, ForkName, Hash256, InclusionList, SignedInclusionList, Slot};
use validator_store::ValidatorStore;

type DependentRoot = Hash256;

struct InclusionListData {
    dependent_root: DependentRoot,
    transactions: InclusionListTransactions,
}

pub struct Inner<S, T> {
    duties_service: Arc<DutiesService<S, T>>,
    validator_store: Arc<S>,
    slot_clock: T,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
}

pub struct InclusionListService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for InclusionListService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for InclusionListService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<S, T> InclusionListService<S, T>
where
    S: ValidatorStore + 'static,
    T: SlotClock + 'static,
{
    pub fn new(
        duties_service: Arc<DutiesService<S, T>>,
        validator_store: Arc<S>,
        slot_clock: T,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        executor: TaskExecutor,
        chain_spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                duties_service,
                validator_store,
                slot_clock,
                beacon_nodes,
                executor,
                chain_spec,
            }),
        }
    }

    pub fn start_update_service(self) -> Result<(), String> {
        info!(
            inclusion_list_due_ms = self.chain_spec.get_inclusion_list_due().as_millis(),
            "Inclusion list service started"
        );
        let executor = self.executor.clone();

        let interval_fut = async move {
            loop {
                if let Err(e) = self.spawn_inclusion_list_tasks().await {
                    error!(error = e, "Failed to produce inclusion lists");
                }
            }
        };

        executor.spawn(interval_fut, "inclusion_list_service");

        Ok(())
    }

    async fn spawn_inclusion_list_tasks(&self) -> Result<(), String> {
        // TODO(heze): consider producing the inclusion list after the slot's envelope is
        // revealed instead of right at the start of the slot, keeping the current approach
        // as a fallback. Producing at slot start means the list can include transactions
        // that the current slot's payload already includes. These would mean redundant constraints
        // that put no pressure on the next builder. Building after the envelopes reveal would
        // keep only still-pending transactions
        let Some(slot) = self.wait_to_next_slot().await else {
            return Ok(());
        };

        let Some((duties, inclusion_list_data)) =
            self.produce_inclusion_list_duties_data(slot).await?
        else {
            return Ok(());
        };

        let service = self.clone();
        self.executor.spawn(
            async move {
                if let Err(e) = service
                    .sign_and_publish(slot, duties, inclusion_list_data)
                    .await
                {
                    crit!(error = e, %slot, "Failed to publish inclusion lists");
                }
            },
            "inclusion_list_producer",
        );
        Ok(())
    }

    async fn wait_to_next_slot(&self) -> Option<Slot> {
        let slot_duration = self.chain_spec.get_slot_duration();

        let Some(duration_to_next_slot) = self.slot_clock.duration_to_next_slot() else {
            error!("Failed to read slot clock");
            sleep(slot_duration).await;
            return None;
        };

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after trigger");
            return None;
        };

        // Ensure that the current slot is in the Heze fork
        if !self
            .chain_spec
            .fork_name_at_slot::<S::E>(current_slot)
            .heze_enabled()
        {
            let duration_to_next_epoch = self
                .slot_clock
                .duration_to_next_epoch(S::E::slots_per_epoch())
                .unwrap_or_else(|| {
                    self.chain_spec.get_slot_duration() * S::E::slots_per_epoch() as u32
                });
            sleep(duration_to_next_epoch).await;
            return None;
        }

        sleep(duration_to_next_slot).await;

        let Some(current_slot) = self.slot_clock.now() else {
            error!("Failed to read slot clock after sleep");
            return None;
        };

        Some(current_slot)
    }

    /// Produce the inclusion list data for `slot`, returned alongside the duties to sign.
    ///
    /// Returns `Ok(None)` when there is nothing to produce (the slot's duties have not been
    /// downloaded yet, or no local validator has an IL duty at the slot) and `Err` when
    /// fetching the inclusion list transactions failed.
    async fn produce_inclusion_list_duties_data(
        &self,
        slot: Slot,
    ) -> Result<Option<(Vec<InclusionListDuty>, InclusionListData)>, String> {
        let Some((dependent_root, duties)) = self.duties_service.get_il_duties_for_slot(slot)
        else {
            return Ok(None);
        };

        if duties.is_empty() {
            return Ok(None);
        }

        debug!(
            %slot,
            il_duties_count = duties.len(),
            "Producing inclusion lists"
        );

        // Fetch the inclusion list transactions for the given slot
        let transactions = self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                beacon_node
                    .get_validator_inclusion_list(slot)
                    .await
                    .map(|resp| resp.data)
            })
            .await
            .map_err(|e| e.to_string())?;

        debug!(
            %slot,
            ?dependent_root,
            tx_count = transactions.transactions.len(),
            tx_bytes = transactions
                .transactions
                .iter()
                .map(|tx| tx.len())
                .sum::<usize>(),
            "Received inclusion list transactions"
        );

        let inclusion_list_data = InclusionListData {
            dependent_root,
            transactions,
        };

        Ok(Some((duties, inclusion_list_data)))
    }

    async fn sign_and_publish(
        &self,
        slot: Slot,
        duties: Vec<InclusionListDuty>,
        inclusion_list_data: InclusionListData,
    ) -> Result<(), String> {
        let mut signed_ils = Vec::with_capacity(duties.len());

        for duty in duties {
            let inclusion_list = InclusionList {
                slot,
                validator_index: duty.validator_index,
                dependent_root: inclusion_list_data.dependent_root,
                transactions: inclusion_list_data.transactions.transactions.clone(),
            };

            match self
                .validator_store
                .sign_inclusion_list(duty.pubkey, inclusion_list)
                .await
            {
                Ok(signed_il) => signed_ils.push(signed_il),
                Err(e) => {
                    crit!(
                        error = ?e,
                        validator = ?duty.pubkey,
                        %slot,
                        "Failed to sign inclusion list"
                    );
                }
            }
        }

        if signed_ils.is_empty() {
            return Ok(());
        }

        let mut ils_published = 0;
        let fork_name = self.chain_spec.fork_name_at_slot::<S::E>(slot);
        for signed_il in &signed_ils {
            match self.publish_inclusion_list(signed_il, fork_name).await {
                Ok(()) => ils_published += 1,
                Err(e) => error!(
                    %slot,
                    validator_index = signed_il.message.validator_index,
                    error = %e,
                    "Failed to publish inclusion list"
                ),
            }
        }

        if ils_published == 0 {
            return Err(format!(
                "Failed to publish any of the {} signed inclusion lists",
                signed_ils.len()
            ));
        }

        info!(
            %slot,
            published = ils_published,
            total = signed_ils.len(),
            "Published inclusion lists"
        );

        Ok(())
    }

    async fn publish_inclusion_list(
        &self,
        signed_il: &SignedInclusionList,
        fork_name: ForkName,
    ) -> Result<(), String> {
        let result = self
            .beacon_nodes
            .first_success(|beacon_node| {
                let inclusion_list = signed_il.clone();
                async move {
                    beacon_node
                        .post_validator_inclusion_list_ssz(&inclusion_list, fork_name)
                        .await
                        .map_err(|e| format!("Failed to publish inclusion list (SSZ): {e:?}"))
                }
            })
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(ssz_err) => {
                debug!(error = %ssz_err, "SSZ publish failed, falling back to JSON");
                self.beacon_nodes
                    .first_success(|beacon_node| {
                        let inclusion_list = signed_il.clone();
                        async move {
                            beacon_node
                                .post_validator_inclusion_list(&inclusion_list, fork_name)
                                .await
                                .map_err(|e| {
                                    format!("Failed to publish inclusion list (JSON): {e:?}")
                                })
                        }
                    })
                    .await
                    .map_err(|e| e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duties_service::DutiesServiceBuilder;
    use futures::FutureExt;
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::test_utils::generate_deterministic_keypair;
    use types::{Domain, Epoch, MainnetEthSpec, SignedRoot};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    type E = MainnetEthSpec;

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: InclusionListService<S, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(num_validators: usize) -> Self {
            Self::new_with_heze_at(num_validators, Epoch::new(0)).await
        }

        async fn new_with_heze_at(num_validators: usize, heze_fork_epoch: Epoch) -> Self {
            let harness = ValidatorClientHarness::new(num_validators).await;

            let mut spec = (*harness.spec).clone();
            spec.heze_fork_epoch = Some(heze_fork_epoch);
            let spec = Arc::new(spec);

            let duties_service = Arc::new(
                DutiesServiceBuilder::new()
                    .validator_store(harness.validator_store.clone())
                    .slot_clock(harness.slot_clock.clone())
                    .beacon_nodes(harness.beacon_nodes.clone())
                    .executor(harness.test_runtime.task_executor.clone())
                    .spec(spec.clone())
                    .build()
                    .unwrap(),
            );

            let service = InclusionListService::new(
                duties_service,
                harness.validator_store.clone(),
                harness.slot_clock.clone(),
                harness.beacon_nodes.clone(),
                harness.test_runtime.task_executor.clone(),
                spec,
            );

            Self { harness, service }
        }

        fn insert_il_duties(&self, slot: Slot, dependent_root: Hash256) {
            let duties = self
                .harness
                .pubkeys
                .iter()
                .enumerate()
                .map(|(i, pubkey)| InclusionListDuty {
                    pubkey: *pubkey,
                    validator_index: i as u64,
                    slot,
                })
                .collect();
            self.service
                .duties_service
                .il_duties
                .write()
                .insert(slot.epoch(E::slots_per_epoch()), (dependent_root, duties));
        }
    }

    async fn advance_time(slot_clock: &ManualSlotClock, duration: Duration) {
        slot_clock.advance_time(duration);
        tokio::time::advance(duration).await;
    }

    /// Pre-Heze the wait sleeps to the next epoch and returns `None`
    /// No duties are read and no BN request is made
    #[tokio::test]
    async fn waits_until_next_epoch_before_heze_fork() {
        tokio::time::pause();

        let harness = TestHarness::new_with_heze_at(1, Epoch::new(1)).await;
        let service = &harness.service;

        // Add duties for a pre-Heze slot
        // If the il task execution leaks past the wait_for_next_slot check,
        // it would fetch the transactions from the mock BNs and fail the final assertion
        // in the test
        harness.insert_il_duties(Slot::new(1), Hash256::repeat_byte(0xab));
        let service_wait = service.spawn_inclusion_list_tasks();
        tokio::pin!(service_wait);

        // This first call of .now_or_never() starts the timer and registers the sleep timer with tokio
        // It calls sleep(duration_to_next_epoch).await which registers a timer with a deadline of 12s * 32
        assert!(service_wait.as_mut().now_or_never().is_none());

        // Advance both slot_clock and tokio::time slot by slot up to 384s (the sleep deadline)
        // This verifies that wait_to_next_slot waits a whole epoch (not just a slot) before completing
        for _ in 0..E::slots_per_epoch() {
            let duration_to_next_slot = harness.service.slot_clock.duration_to_next_slot().unwrap();
            advance_time(&harness.service.slot_clock, duration_to_next_slot).await;
            assert!(
                service_wait.as_mut().now_or_never().is_none(),
                "Function should return None before the sleep duration has elapsed"
            );
        }

        // Advance time for 1 more second, past the epoch boundary.
        // The epoch sleep should have completed and the execution should complete as a no-op.
        // This call should yield no slot, so nothing should be produced, signed or published.
        advance_time(&harness.service.slot_clock, Duration::from_secs(1)).await;
        assert_eq!(service_wait.as_mut().now_or_never(), Some(Ok(())));
    }

    #[tokio::test]
    async fn waits_until_next_slot() {
        tokio::time::pause();

        let harness = TestHarness::new_with_validators(1).await;
        let service = &harness.service;
        let service_wait = service.wait_to_next_slot();
        tokio::pin!(service_wait);

        // Start the timer and registers the sleep timer with tokio
        assert!(service_wait.as_mut().now_or_never().is_none());

        let duration_to_wait = harness.service.slot_clock.duration_to_next_slot().unwrap();
        // Advance both slot_clock and tokio::time to 12s
        advance_time(&harness.service.slot_clock, duration_to_wait).await;
        assert!(
            service_wait.as_mut().now_or_never().is_none(),
            "Function should return None before the sleep duration has elapsed"
        );

        advance_time(&harness.service.slot_clock, Duration::from_secs(1)).await;
        assert_eq!(
            service_wait.as_mut().now_or_never().unwrap(),
            Some(Slot::new(1))
        );
    }

    #[tokio::test]
    async fn no_duties_no_fetch_no_publish() {
        let mut harness = TestHarness::new_with_validators(3).await;
        let current_slot = harness.service.slot_clock.now().unwrap();

        let transactions = InclusionListTransactions {
            transactions: Default::default(),
        };
        let fetch_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, current_slot);
        let publish_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz(ForkName::Heze);

        // Duties for the slot's epoch not downloaded yet
        let result = harness
            .service
            .produce_inclusion_list_duties_data(current_slot)
            .await;
        assert!(result.unwrap().is_none());

        // Add duty for next slot, not for the current one
        harness.insert_il_duties(current_slot + 1, Hash256::repeat_byte(0xab));
        let result = harness
            .service
            .produce_inclusion_list_duties_data(current_slot)
            .await;
        assert!(result.unwrap().is_none());

        fetch_mock.expect(0).assert();
        publish_mock.expect(0).assert();
    }

    /// Produce endpoint fails on all BNs: produce returns `Err`, nothing is signed or
    /// published, and the main service loop handles the error
    #[tokio::test]
    async fn produce_fetch_error_aborts_slot() {
        let mut harness = TestHarness::new_with_validators(3).await;
        let slot = Slot::new(1);
        harness.insert_il_duties(slot, Hash256::repeat_byte(0xab));

        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list_error(slot);
        harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_inclusion_list_error(slot);

        let result = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await;
        assert!(result.is_err());
    }

    /// First BN errors on the produce endpoint, second serves: `first_success` walks
    /// past and transactions come from the second BN.
    #[tokio::test]
    async fn produce_falls_back_to_second_bn() {
        let mut harness = TestHarness::new_with_validators(3).await;
        let slot = Slot::new(1);
        let dependent_root = Hash256::repeat_byte(0xab);
        harness.insert_il_duties(slot, dependent_root);

        let transactions = InclusionListTransactions {
            transactions: vec![vec![0xaa; 3].try_into().unwrap()].try_into().unwrap(),
        };
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list_error(slot);
        let bn2_mock = harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_inclusion_list(&transactions, slot);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(duties.len(), 3);
        assert_eq!(data.dependent_root, dependent_root);
        assert_eq!(data.transactions, transactions);
        bn2_mock.expect(1).assert();
    }

    #[tokio::test]
    async fn publishes_each_inclusion_list_via_ssz() {
        let mut harness = TestHarness::new_with_validators(3).await;
        let slot = Slot::new(1);
        let dependent_root = Hash256::repeat_byte(0xab);
        harness.insert_il_duties(slot, dependent_root);

        let transactions = InclusionListTransactions {
            transactions: vec![vec![0xaa; 3].try_into().unwrap()].try_into().unwrap(),
        };
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, slot);
        let ssz_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz(ForkName::Heze);
        let json_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_json(ForkName::Heze);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        harness
            .service
            .sign_and_publish(slot, duties, data)
            .await
            .unwrap();

        // One POST per duty,and no JSON fallback
        ssz_mock.expect(3).assert();
        json_mock.expect(0).assert();

        let messages = harness
            .harness
            .mock_beacon_node_1
            .received_inclusion_lists
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 3);

        // Check each message
        for (i, signed_il) in messages.iter().enumerate() {
            assert_eq!(signed_il.message.validator_index, i as u64);
            assert_eq!(signed_il.message.slot, slot);
            assert_eq!(signed_il.message.dependent_root, dependent_root);
            assert_eq!(signed_il.message.transactions, transactions.transactions);
        }
        // Each message carries its own validator's signature
        assert_ne!(messages[0].signature, messages[1].signature);
        assert_ne!(messages[1].signature, messages[2].signature);
    }

    #[tokio::test]
    async fn inclusion_list_ssz_publish_falls_back_to_json() {
        let mut harness = TestHarness::new_with_validators(1).await;
        let slot = Slot::new(1);
        harness.insert_il_duties(slot, Hash256::repeat_byte(0xab));

        let transactions = InclusionListTransactions {
            transactions: Default::default(),
        };
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, slot);
        let ssz_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz_error(ForkName::Heze);
        let json_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_json(ForkName::Heze);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        harness
            .service
            .sign_and_publish(slot, duties, data)
            .await
            .unwrap();

        // `first_success` makes two passes over the BNs, so the failing SSZ mock is hit twice
        ssz_mock.expect(2).assert();
        json_mock.expect(1).assert();

        let messages = harness
            .harness
            .mock_beacon_node_1
            .received_inclusion_lists
            .lock()
            .unwrap();
        assert_eq!(messages.len(), 1);
    }

    /// One duty's publish fails on both encodings
    /// so the succeeded calls are total - 1
    #[tokio::test]
    async fn partial_publish_failure_still_publishes_siblings() {
        let mut harness = TestHarness::new_with_validators(2).await;
        let slot = Slot::new(1);
        harness.insert_il_duties(slot, Hash256::repeat_byte(0xab));

        let transactions = InclusionListTransactions {
            transactions: Default::default(),
        };
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, slot);

        // Each error mock answers exactly one request: the first duty's publish fails on
        // both `first_success` passes of both encodings
        let ssz_err_1 = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz_error(ForkName::Heze);
        let json_err_1 = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_json_error(ForkName::Heze);
        let ssz_err_2 = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz_error(ForkName::Heze);
        let json_err_2 = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_json_error(ForkName::Heze);
        // With the error mocks above spent, the sibling duty publishes here
        let ssz_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz(ForkName::Heze);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        harness
            .service
            .sign_and_publish(slot, duties, data)
            .await
            .unwrap();

        ssz_err_1.expect(1).assert();
        ssz_err_2.expect(1).assert();
        json_err_1.expect(1).assert();
        json_err_2.expect(1).assert();
        // successful call
        ssz_mock.expect(1).assert();

        let messages = harness
            .harness
            .mock_beacon_node_1
            .received_inclusion_lists
            .lock()
            .unwrap();
        let indices: Vec<u64> = messages
            .iter()
            .map(|il| il.message.validator_index)
            .collect();
        assert_eq!(indices, vec![1]);
    }

    #[tokio::test]
    async fn total_publish_failure_returns_error() {
        let mut harness = TestHarness::new_with_validators(2).await;
        let slot = Slot::new(1);
        harness.insert_il_duties(slot, Hash256::repeat_byte(0xab));

        let transactions = InclusionListTransactions {
            transactions: Default::default(),
        };
        // No POST routes are registered: every publish fails on both encodings
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, slot);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        let result = harness.service.sign_and_publish(slot, duties, data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn signed_inclusion_list_verifies_against_consensus_signature_check() {
        let harness = TestHarness::new_with_validators(1).await;
        let slot = Slot::new(1);
        let pubkey = harness.harness.pubkeys[0];

        let inclusion_list = InclusionList {
            slot,
            validator_index: 0,
            dependent_root: Hash256::repeat_byte(0xab),
            transactions: Default::default(),
        };
        let signed = harness
            .harness
            .validator_store
            .sign_inclusion_list(pubkey, inclusion_list)
            .await
            .unwrap();

        // Independent consensus-side derivation
        let spec = &harness.harness.spec;
        let epoch = slot.epoch(E::slots_per_epoch());
        let fork = spec.fork_at_epoch(epoch);
        let domain = spec.get_domain(epoch, Domain::InclusionListCommittee, &fork, Hash256::ZERO);
        let signing_root = signed.message.signing_root(domain);
        assert!(
            signed
                .signature
                .verify(&pubkey.decompress().unwrap(), signing_root)
        );
    }

    #[tokio::test]
    async fn sign_failure_for_unknown_validator_skips_publish() {
        let mut harness = TestHarness::new_with_validators(1).await;
        let slot = Slot::new(1);

        // A duty for a validator the store does not hold
        let duty = InclusionListDuty {
            pubkey: generate_deterministic_keypair(99).pk.into(),
            validator_index: 99,
            slot,
        };
        harness.service.duties_service.il_duties.write().insert(
            slot.epoch(E::slots_per_epoch()),
            (Hash256::repeat_byte(0xab), vec![duty]),
        );

        let transactions = InclusionListTransactions {
            transactions: Default::default(),
        };
        harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_inclusion_list(&transactions, slot);
        let ssz_mock = harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_inclusion_list_ssz(ForkName::Heze);

        let (duties, data) = harness
            .service
            .produce_inclusion_list_duties_data(slot)
            .await
            .unwrap()
            .unwrap();
        let result = harness.service.sign_and_publish(slot, duties, data).await;

        // Nothing signed means nothing to publish, not a total publish failure
        assert_eq!(result, Ok(()));
        ssz_mock.expect(0).assert();
    }
}

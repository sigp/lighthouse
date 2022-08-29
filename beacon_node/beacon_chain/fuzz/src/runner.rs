use crate::{Config, Hydra, LogConfig, Message, Node, TestHarness};
use arbitrary::Unstructured;
use beacon_chain::beacon_proposer_cache::compute_proposer_duties_from_head;
use beacon_chain::slot_clock::SlotClock;
use beacon_chain::test_utils::test_spec;
use std::collections::VecDeque;
use std::ops::ControlFlow;
use std::time::Duration;
use types::{test_utils::generate_deterministic_keypairs, *};

// FIXME(hydra): add slashing protection
pub struct Runner<'a, E: EthSpec> {
    conf: Config,
    honest_nodes: Vec<Node<E>>,
    attacker: Node<E>,
    hydra: Hydra<E>,
    u: Unstructured<'a>,
    time: CurrentTime,
    all_blocks: Vec<(Hash256, Slot)>,
    spec: ChainSpec,
}

pub struct CurrentTime {
    tick: usize,
    current_time: Duration,
    tick_duration: Duration,
}

impl CurrentTime {
    fn increment(&mut self) {
        self.tick += 1;
        self.current_time += self.tick_duration;
    }
}

impl<'a, E: EthSpec> Runner<'a, E> {
    pub fn new(
        data: &'a [u8],
        conf: Config,
        get_harness: impl for<'b> Fn(String, LogConfig, &'b [Keypair]) -> TestHarness<E>,
    ) -> Self {
        assert!(conf.is_valid());

        let u = Unstructured::new(data);
        let spec = test_spec::<E>();

        let keypairs = generate_deterministic_keypairs(conf.total_validators);

        // Create honest nodes.
        let validators_per_node = conf.honest_validators_per_node();
        let honest_nodes = (0..conf.num_honest_nodes)
            .map(|i| {
                let id = format!("node_{i}");
                let log_config = conf.log_config(i);
                let harness = get_harness(id.clone(), log_config, &keypairs);
                let validators = (i * validators_per_node..(i + 1) * validators_per_node).collect();
                Node {
                    id,
                    harness,
                    message_queue: VecDeque::new(),
                    validators,
                }
            })
            .collect::<Vec<_>>();

        // Set up attacker values.
        let attacker_id = "attacker".to_string();
        let attacker = Node {
            id: attacker_id.clone(),
            harness: get_harness(attacker_id, conf.attacker_log_config(), &keypairs),
            message_queue: VecDeque::new(),
            validators: (conf.honest_validators()..conf.total_validators).collect(),
        };
        let hydra = Hydra::default();

        // Simulation parameters.
        let time = CurrentTime {
            tick: 0,
            current_time: *attacker.harness.chain.slot_clock.genesis_duration(),
            tick_duration: conf.tick_duration(&spec),
        };

        let all_blocks = vec![(attacker.harness.head_block_root(), Slot::new(0))];

        Runner {
            conf,
            honest_nodes,
            attacker,
            hydra,
            u,
            time,
            all_blocks,
            spec,
        }
    }

    fn tick(&self) -> usize {
        self.time.tick
    }

    fn current_slot(&self) -> Slot {
        self.attacker.harness.chain.slot_clock.now().unwrap()
    }

    fn current_epoch(&self) -> Epoch {
        self.current_slot().epoch(E::slots_per_epoch())
    }

    fn record_block_proposal(&mut self, block: &SignedBeaconBlock<E>) {
        let block_root = block.canonical_root();
        let slot = block.slot();
        if self.conf.debug.block_proposals {
            println!(
                "block {:?} @ slot {}, parent: {:?}",
                block_root,
                slot,
                block.parent_root()
            );
        }
        self.all_blocks.push((block_root, slot));
    }

    async fn queue_all_with_random_delay(&mut self, message: Message<E>) -> arbitrary::Result<()> {
        // Choose the delay for the message to reach the first honest node.
        let first_node_delay = self.u.int_in_range(0..=self.conf.max_first_node_delay)?;

        // Choose that node.
        let first_node = self.u.choose_index(self.honest_nodes.len())?;

        // Choose the delays for the other nodes randomly within the configured range.
        for (i, node) in self.honest_nodes.iter_mut().enumerate() {
            let delay = if i == first_node {
                first_node_delay
            } else {
                self.u.int_in_range(
                    first_node_delay..=first_node_delay + self.conf.max_delay_difference,
                )?
            };
            node.queue_message(message.clone(), self.time.tick + delay);
        }

        // Deliver the message to the attacker's node instantly.
        self.attacker.deliver_message(message).await;

        Ok(())
    }

    async fn deliver_all_honest(&self, message: &Message<E>) {
        for node in &self.honest_nodes {
            node.deliver_message(message.clone()).await;
        }
    }

    async fn deliver_all(&self, message: Message<E>) {
        self.deliver_all_honest(&message).await;
        self.attacker.deliver_message(message).await;
    }

    /// Update time and deliver queued messages on all nodes.
    async fn on_clock_advance(&mut self) {
        // Update the Hydra as we use it to determine block viability.
        let current_epoch = self.current_epoch();
        self.hydra
            .update(&self.attacker.harness, current_epoch, &self.spec);

        for node in &mut self.honest_nodes {
            node.harness
                .chain
                .slot_clock
                .set_current_time(self.time.current_time);

            // Run fork choice at every slot boundary.
            if self.conf.is_block_proposal_tick(self.time.tick) {
                node.harness.chain.per_slot_task().await;
            }

            node.deliver_queued_at(self.time.tick, |block_root| {
                self.hydra.block_is_viable(&block_root)
            })
            .await;
        }

        self.attacker
            .harness
            .chain
            .slot_clock
            .set_current_time(self.time.current_time);
        if self.conf.is_block_proposal_tick(self.tick()) {
            self.attacker.harness.chain.per_slot_task().await;
        }
    }

    pub async fn run(&mut self) -> arbitrary::Result<()> {
        let slots_per_epoch = E::slots_per_epoch() as usize;

        // Generate events while the input is non-empty.
        while !self.u.is_empty() {
            let current_slot = self.current_slot();
            let current_epoch = self.current_epoch();

            // Slot start activities for honest nodes.
            if self.conf.is_block_proposal_tick(self.tick()) {
                let mut new_blocks = vec![];

                // Produce block(s).
                for node in &mut self.honest_nodes {
                    let (proposers, _, _, _) =
                        compute_proposer_duties_from_head(current_epoch, &node.harness.chain)
                            .unwrap();
                    let current_slot_proposer =
                        proposers[current_slot.as_usize() % slots_per_epoch];

                    if !node.validators.contains(&current_slot_proposer) {
                        continue;
                    }

                    let head_state = node.harness.get_current_state();
                    let (block, _) = node.harness.make_block(head_state, current_slot).await;
                    new_blocks.push(block);
                }

                // New honest blocks get delivered instantly.
                for block in new_blocks {
                    self.record_block_proposal(&block);
                    self.deliver_all(Message::Block(block)).await;
                }
            }

            // Unaggregated attestations from the honest nodes.
            if self.conf.is_attestation_tick(self.tick()) {
                let mut new_attestations = vec![];
                for node in &self.honest_nodes {
                    let head = node.harness.chain.canonical_head.cached_head();
                    let attestations = node.harness.make_unaggregated_attestations(
                        &node.validators,
                        &head.snapshot.beacon_state,
                        head.head_state_root(),
                        head.head_block_root().into(),
                        current_slot,
                    );
                    new_attestations.extend(
                        attestations
                            .into_iter()
                            .flat_map(|atts| atts.into_iter().map(|(att, _)| att)),
                    );
                }
                for attestation in new_attestations {
                    self.deliver_all(Message::Attestation(attestation)).await;
                }
            }

            // Slot start activities for the attacker.
            if self.conf.is_block_proposal_tick(self.tick()) {
                self.hydra
                    .update(&self.attacker.harness, current_epoch, &self.spec);
                let proposer_heads = self.hydra.proposer_heads_at_slot(
                    current_slot,
                    &self.attacker.validators,
                    &self.spec,
                );
                if self.conf.debug.num_hydra_heads {
                    println!(
                        "number of hydra heads at slot {}: {}, attacker proposers: {}",
                        current_slot,
                        self.hydra.num_heads(),
                        proposer_heads.len(),
                    );
                }

                if !proposer_heads.is_empty() {
                    let mut proposers = proposer_heads.iter();
                    let mut selected_proposals = vec![];

                    self.u.arbitrary_loop(
                        self.conf.min_attacker_proposers(proposers.len()),
                        self.conf.max_attacker_proposers(proposers.len()),
                        |ux| {
                            let (_, head_choices) = proposers.next().unwrap();
                            let (block_root, state_ref) = ux.choose(&head_choices)?;
                            let state: BeaconState<E> = (*state_ref).clone();

                            selected_proposals.push((block_root, state));
                            Ok(ControlFlow::Continue(()))
                        },
                    )?;

                    let mut new_blocks = vec![];

                    for (_, state) in selected_proposals {
                        let (block, _) =
                            self.attacker.harness.make_block(state, current_slot).await;
                        if self.conf.debug.attacker_proposals {
                            println!(
                                "attacker proposed block {:?} at slot {} atop {:?}",
                                block.canonical_root(),
                                current_slot,
                                block.parent_root(),
                            );
                        }
                        new_blocks.push(block);
                    }

                    for block in new_blocks {
                        self.record_block_proposal(&block);
                        self.queue_all_with_random_delay(Message::Block(block))
                            .await?;
                    }
                }
            }

            // Increment clock on each node and deliver messages.
            self.time.increment();
            self.on_clock_advance().await;
        }

        // Keep running until all message queues are empty.
        while self
            .honest_nodes
            .iter()
            .any(|node| node.has_messages_queued())
        {
            self.time.increment();
            self.on_clock_advance().await;
        }

        println!(
            "finished a run that generated {} blocks up to slot {}",
            self.all_blocks.len(),
            self.all_blocks.iter().map(|(_, slot)| slot).max().unwrap()
        );
        Ok(())
    }
}

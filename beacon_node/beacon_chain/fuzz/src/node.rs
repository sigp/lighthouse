use crate::{config::DebugConfig, Message, SlashingProtection, TestHarness};
use async_recursion::async_recursion;
use beacon_chain::{AttestationError, BeaconChainError, BlockError, ForkChoiceError};
use fork_choice::InvalidAttestation;
use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::VecDeque;
use types::{Attestation, EthSpec, Hash256, Slot};

pub struct Node<E: EthSpec> {
    pub id: String,
    pub harness: TestHarness<E>,
    /// Queue of ordered `(tick, message)` pairs.
    ///
    /// Each `message` will be delivered to the node at `tick`.
    pub message_queue: VecDeque<(usize, Message<E>)>,
    /// Messages that are dependent on others, to be processed immediately once their dependent
    /// block is processed.
    pub dependent_messages: HashMap<Hash256, Vec<Message<E>>>,
    /// Validator indices assigned to this node.
    pub validators: Vec<usize>,
    /// Slashing protection for validators assigned to this node.
    pub slashing_protection: SlashingProtection,
    pub debug_config: DebugConfig,
}

impl<E: EthSpec> Node<E> {
    pub fn queue_message(&mut self, message: Message<E>, arrive_tick: usize) {
        let insert_at = self
            .message_queue
            .partition_point(|&(tick, _)| tick <= arrive_tick);
        self.message_queue.insert(insert_at, (arrive_tick, message));
    }

    pub fn has_messages_queued(&self) -> bool {
        !self.message_queue.is_empty()
    }

    /// Deliver the message, or cache it in the dependent messages for later processing.
    #[async_recursion]
    pub async fn deliver_message(&mut self, message: Message<E>) {
        let unblocking_block_root = message.is_block().then(|| message.block_root());

        if let Some(undelivered) = self.try_deliver_message(message).await {
            if undelivered.is_block() && self.debug_config.block_delivery {
                println!(
                    "{}: queueing block {:?} in dependent messages",
                    self.id,
                    undelivered.block_root()
                );
            }
            self.dependent_messages
                .entry(undelivered.dependent_block_root())
                .or_insert_with(Vec::new)
                .push(undelivered);
        } else if let Some(unblocking_root) = unblocking_block_root {
            if self.debug_config.block_delivery {
                println!("{}: processed block {:?}", self.id, unblocking_root);
            }

            // Block was delivered successfully: process all messages dependent on this block.
            if let Some(messages) = self.dependent_messages.remove(&unblocking_root) {
                for message in messages {
                    self.deliver_message(message).await;
                }
            }
        }
    }

    /// Attempt to deliver the message, returning it if is unable to be processed right now.
    ///
    /// Undelivered messages should be requeued to simulate the node queueing them outside the
    /// `BeaconChain` module, or fetching them via network RPC.
    async fn try_deliver_message(&self, message: Message<E>) -> Option<Message<E>> {
        match message {
            Message::Attestation(att) => match self
                .harness
                .process_unaggregated_attestation(att.clone())
            {
                Ok(()) => None,
                // Re-queue attestations for which the head block is not yet known.
                Err(AttestationError::UnknownHeadBlock { .. }) => Some(Message::Attestation(att)),
                // Ignore attestations from past slots.
                Err(AttestationError::PastSlot { .. }) => None,
                // Workaround for a minor bug: https://github.com/sigp/lighthouse/issues/4633
                Err(AttestationError::BeaconChainError(BeaconChainError::ForkChoiceError(
                    ForkChoiceError::InvalidAttestation(InvalidAttestation::PastEpoch { .. }),
                ))) => None,
                Err(e) => panic!("unable to deliver attestation to node {}: {e:?}", self.id),
            },
            Message::Block(block) => {
                match self.harness.process_block_result(block).await {
                    Ok(_) => None,
                    // Re-queue blocks that arrive out of order.
                    Err(BlockError::ParentUnknown(block)) => Some(Message::Block((*block).clone())),
                    // If a block arrives after the node has already finalized a conflicting block
                    // then it is useless and doesn't need to be reprocessed.
                    Err(
                        BlockError::WouldRevertFinalizedSlot { .. }
                        | BlockError::NotFinalizedDescendant { .. },
                    ) => None,
                    Err(e) => panic!("unable to process block: {e:?}"),
                }
            }
        }
    }

    pub async fn deliver_queued_at(&mut self, tick: usize) {
        loop {
            match self.message_queue.front() {
                Some((message_tick, _)) if *message_tick <= tick => {
                    let (_, message) = self.message_queue.pop_front().unwrap();
                    self.deliver_message(message).await;
                }
                _ => break,
            }
        }
    }

    pub fn prune_dependent_messages(&mut self, block_is_viable: impl Fn(Hash256) -> bool) {
        self.dependent_messages
            .retain(|block_root, _| block_is_viable(*block_root));
    }

    /// Produce unaggregated attestations for all (honest) validators managed by this node.
    ///
    /// Do not produce attestations if they are slashable.
    pub fn get_honest_unaggregated_attestations(
        &mut self,
        attestation_slot: Slot,
    ) -> Vec<Attestation<E>> {
        let head = self.harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let head_block_root = head.head_block_root();
        let state_root = head.head_state_root();
        let fork = self
            .harness
            .chain
            .spec
            .fork_at_epoch(attestation_slot.epoch(E::slots_per_epoch()));

        let mut attestations = vec![];
        for bc in state
            .get_beacon_committees_at_slot(attestation_slot)
            .unwrap()
        {
            for (committee_position, &validator_index) in bc.committee.iter().enumerate() {
                if !self.validators.contains(&validator_index) {
                    continue;
                }

                let mut attestation = self
                    .harness
                    .produce_unaggregated_attestation_for_block(
                        attestation_slot,
                        bc.index,
                        head_block_root.into(),
                        Cow::Borrowed(state),
                        state_root,
                    )
                    .unwrap();

                // Check slashability.
                if !self.slashing_protection.can_attest(
                    validator_index,
                    attestation.data.source.epoch,
                    attestation.data.target.epoch,
                ) {
                    continue;
                }
                self.slashing_protection.record_attestation(
                    validator_index,
                    attestation.data.source.epoch,
                    attestation.data.target.epoch,
                );

                attestation
                    .sign(
                        &self.harness.validator_keypairs[validator_index].sk,
                        committee_position,
                        &fork,
                        self.harness.chain.genesis_validators_root,
                        &self.harness.spec,
                    )
                    .unwrap();

                attestations.push(attestation);
            }
        }
        attestations
    }
}

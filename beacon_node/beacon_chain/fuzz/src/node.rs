use crate::{Message, TestHarness};
use beacon_chain::{AttestationError, BlockError};
use std::collections::VecDeque;
use types::{EthSpec, Hash256};

const LOG_BLOCK_DELIVERY: bool = false;

pub struct Node<E: EthSpec> {
    pub id: String,
    pub harness: TestHarness<E>,
    /// Queue of ordered `(tick, message)` pairs.
    ///
    /// Each `message` will be delivered to the node at `tick`.
    pub message_queue: VecDeque<(usize, Message<E>)>,
    /// Validator indices assigned to this node.
    pub validators: Vec<usize>,
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

    pub fn last_message_tick(&self, current_tick: usize) -> usize {
        self.message_queue
            .back()
            .map_or(current_tick, |(tick, _)| *tick)
    }

    /// Attempt to deliver the message, returning it if is unable to be processed right now.
    ///
    /// Undelivered messages should be requeued to simulate the node queueing them outside the
    /// `BeaconChain` module, or fetching them via network RPC.
    pub async fn deliver_message(&self, message: Message<E>) -> Option<Message<E>> {
        match message {
            Message::Attestation(att) => match self
                .harness
                .process_unaggregated_attestation(att.clone())
            {
                Ok(()) => None,
                // Re-queue attestations for which the head block is not yet known.
                Err(AttestationError::UnknownHeadBlock { .. }) => Some(Message::Attestation(att)),
                Err(e) => panic!("unable to deliver attestation: {e:?}"),
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

    pub async fn deliver_queued_at(
        &mut self,
        tick: usize,
        block_is_viable: impl Fn(Hash256) -> bool + Copy,
    ) {
        loop {
            match self.message_queue.front() {
                Some((message_tick, _)) if *message_tick <= tick => {
                    let (message_tick, message) = self.message_queue.pop_front().unwrap();

                    let block_root = message.block_root();

                    if message.is_block() && LOG_BLOCK_DELIVERY {
                        println!(
                            "{}: attempting to process block {:?} at tick {}/{}",
                            self.id, block_root, message_tick, tick
                        );
                    }

                    if let Some(undelivered) = self.deliver_message(message).await {
                        if block_is_viable(block_root) {
                            let requeue_tick = self.last_message_tick(tick);
                            self.queue_message(undelivered, requeue_tick);
                        }
                    }
                }
                _ => break,
            }
        }
    }
}

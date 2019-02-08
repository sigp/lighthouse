use super::direct_beacon_node::DirectBeaconNode;
use super::direct_duties::DirectDuties;
use super::local_signer::LocalSigner;
use attester::PollOutcome as AttestationPollOutcome;
use attester::{Attester, Error as AttestationPollError};
use beacon_chain::BeaconChain;
use block_proposer::PollOutcome as BlockPollOutcome;
use block_proposer::{BlockProposer, Error as BlockPollError};
use db::MemoryDB;
use slot_clock::TestingSlotClock;
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, FreeAttestation, Keypair, Slot};

#[derive(Debug, PartialEq)]
pub enum BlockProposeError {
    DidNotPropose(BlockPollOutcome),
    PollError(BlockPollError),
}

#[derive(Debug, PartialEq)]
pub enum AttestationProposeError {
    DidNotPropose(AttestationPollOutcome),
    PollError(AttestationPollError),
}

/// A `BlockProposer` and `Attester` which sign using a common keypair.
///
/// The test validator connects directly to a borrowed `BeaconChain` struct. It is useful for
/// testing that the core proposer and attester logic is functioning. Also for supporting beacon
/// chain tests.
pub struct ValidatorHarness {
    pub block_proposer: BlockProposer<
        TestingSlotClock,
        DirectBeaconNode<MemoryDB, TestingSlotClock>,
        DirectDuties<MemoryDB, TestingSlotClock>,
        LocalSigner,
    >,
    pub attester: Attester<
        TestingSlotClock,
        DirectBeaconNode<MemoryDB, TestingSlotClock>,
        DirectDuties<MemoryDB, TestingSlotClock>,
        LocalSigner,
    >,
    pub spec: Arc<ChainSpec>,
    pub epoch_map: Arc<DirectDuties<MemoryDB, TestingSlotClock>>,
    pub keypair: Keypair,
    pub beacon_node: Arc<DirectBeaconNode<MemoryDB, TestingSlotClock>>,
    pub slot_clock: Arc<TestingSlotClock>,
    pub signer: Arc<LocalSigner>,
}

impl ValidatorHarness {
    /// Create a new ValidatorHarness that signs with the given keypair, operates per the given spec and connects to the
    /// supplied beacon node.
    ///
    /// A `BlockProposer` and `Attester` is created..
    pub fn new(
        keypair: Keypair,
        beacon_chain: Arc<BeaconChain<MemoryDB, TestingSlotClock>>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        let slot_clock = Arc::new(TestingSlotClock::new(spec.genesis_slot.as_u64()));
        let signer = Arc::new(LocalSigner::new(keypair.clone()));
        let beacon_node = Arc::new(DirectBeaconNode::new(beacon_chain.clone()));
        let epoch_map = Arc::new(DirectDuties::new(keypair.pk.clone(), beacon_chain.clone()));

        let block_proposer = BlockProposer::new(
            spec.clone(),
            keypair.pk.clone(),
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        let attester = Attester::new(
            epoch_map.clone(),
            slot_clock.clone(),
            beacon_node.clone(),
            signer.clone(),
        );

        Self {
            block_proposer,
            attester,
            spec,
            epoch_map,
            keypair,
            beacon_node,
            slot_clock,
            signer,
        }
    }

    /// Run the `poll` function on the `BlockProposer` and propose a block.
    ///
    /// An error is returned if the proposer refuses to propose.
    pub fn propose_block(&mut self) -> Result<BeaconBlock, BlockProposeError> {
        // Using `DirectBeaconNode`, the validator will always return sucessufully if it tries to
        // publish a block.
        match self.block_proposer.poll() {
            Ok(BlockPollOutcome::BlockProposed(_)) => {}
            Ok(outcome) => return Err(BlockProposeError::DidNotPropose(outcome)),
            Err(error) => return Err(BlockProposeError::PollError(error)),
        };
        Ok(self
            .beacon_node
            .last_published_block()
            .expect("Unable to obtain proposed block."))
    }

    /// Run the `poll` function on the `Attester` and propose a `FreeAttestation`.
    ///
    /// An error is returned if the attester refuses to attest.
    pub fn propose_free_attestation(&mut self) -> Result<FreeAttestation, AttestationProposeError> {
        match self.attester.poll() {
            Ok(AttestationPollOutcome::AttestationProposed(_)) => {}
            Ok(outcome) => return Err(AttestationProposeError::DidNotPropose(outcome)),
            Err(error) => return Err(AttestationProposeError::PollError(error)),
        };
        Ok(self
            .beacon_node
            .last_published_free_attestation()
            .expect("Unable to obtain proposed attestation."))
    }

    /// Set the validators slot clock to the specified slot.
    ///
    /// The validators slot clock will always read this value until it is set to something else.
    pub fn set_slot(&mut self, slot: Slot) {
        self.slot_clock.set_slot(slot.as_u64())
    }
}

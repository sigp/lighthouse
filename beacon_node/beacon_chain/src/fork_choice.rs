use crate::{errors::BeaconChainError, metrics, BeaconChain, BeaconChainTypes};
use parking_lot::RwLock;
use proto_array_fork_choice::ProtoArrayForkChoice;
use ssz_derive::{Decode, Encode};
use state_processing::common::get_attesting_indices;
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Error as StoreError;
use types::{
    Attestation, BeaconBlock, BeaconState, BeaconStateError, Checkpoint, Epoch, EthSpec, Hash256,
    Slot,
};

/// If `true`, fork choice will be dumped to a JSON file in `/tmp` whenever find head fail.
pub const FORK_CHOICE_DEBUGGING: bool = true;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingBlock(Hash256),
    MissingState(Hash256),
    BackendError(String),
    BeaconStateError(BeaconStateError),
    StoreError(StoreError),
    BeaconChainError(Box<BeaconChainError>),
    UnknownBlockSlot(Hash256),
}

#[derive(PartialEq, Clone, Encode, Decode)]
struct CheckpointBalances {
    epoch: Epoch,
    root: Hash256,
    balances: Vec<u64>,
}

impl Into<Checkpoint> for CheckpointBalances {
    fn into(self) -> Checkpoint {
        Checkpoint {
            epoch: self.epoch,
            root: self.root,
        }
    }
}

#[derive(PartialEq, Clone, Encode, Decode)]
struct FFGCheckpoints {
    justified: CheckpointBalances,
    finalized: Checkpoint,
}

#[derive(PartialEq, Clone, Encode, Decode)]
struct CheckpointManager {
    current: FFGCheckpoints,
    best: FFGCheckpoints,
    update_at: Option<Epoch>,
}

impl CheckpointManager {
    pub fn new(genesis_checkpoint: CheckpointBalances) -> Self {
        let ffg_checkpoint = FFGCheckpoints {
            justified: genesis_checkpoint.clone(),
            finalized: genesis_checkpoint.into(),
        };
        Self {
            current: ffg_checkpoint.clone(),
            best: ffg_checkpoint,
            update_at: None,
        }
    }

    pub fn update<T: BeaconChainTypes>(&mut self, chain: &BeaconChain<T>) -> Result<()> {
        if self.best.justified.epoch > self.current.justified.epoch {
            let current_slot = chain.slot()?;
            let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());

            match self.update_at {
                None => {
                    if Self::compute_slots_since_epoch_start::<T>(current_slot)
                        < chain.spec.safe_slots_to_update_justified
                    {
                        self.current = self.best.clone();
                    } else {
                        self.update_at = Some(current_epoch + 1)
                    }
                }
                Some(epoch) if epoch <= current_epoch => {
                    self.current = self.best.clone();
                    self.update_at = None
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Checks the given `state` to see if it contains a `current_justified_checkpoint` that is
    /// better than `self.best_justified_checkpoint`. If so, the value is updated.
    ///
    /// Note: this does not update `self.justified_checkpoint`.
    pub fn process_state<T: BeaconChainTypes>(
        &mut self,
        state: &BeaconState<T::EthSpec>,
        chain: &BeaconChain<T>,
        proto_array: &ProtoArrayForkChoice,
    ) -> Result<()> {
        // Only proceeed if the new checkpoint is better than our current checkpoint.
        if state.current_justified_checkpoint.epoch > self.current.justified.epoch
            && state.finalized_checkpoint.epoch >= self.current.finalized.epoch
        {
            let candidate = FFGCheckpoints {
                justified: CheckpointBalances {
                    epoch: state.current_justified_checkpoint.epoch,
                    root: state.current_justified_checkpoint.root,
                    balances: state.balances.clone().into(),
                },
                finalized: state.finalized_checkpoint.clone(),
            };

            // From the given state, read the block root at first slot of
            // `self.justified_checkpoint.epoch`. If that root matches, then
            // `new_justified_checkpoint` is a descendant of `self.justified_checkpoint` and we may
            // proceed (see next `if` statement).
            let new_checkpoint_ancestor = Self::get_block_root_at_slot(
                state,
                chain,
                candidate.justified.root,
                self.current
                    .justified
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch()),
            )?;

            let candidate_justified_block_slot = proto_array
                .block_slot(&candidate.justified.root)
                .ok_or_else(|| Error::UnknownBlockSlot(candidate.justified.root))?;

            // If the new justified checkpoint is an ancestor of the current justified checkpoint,
            // it is always safe to change it.
            if new_checkpoint_ancestor == Some(self.current.justified.root)
                && candidate_justified_block_slot
                    >= candidate
                        .justified
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch())
            {
                self.current = candidate.clone()
            }

            if candidate.justified.epoch > self.best.justified.epoch {
                // Always update the best checkpoint, if it's better.
                self.best = candidate;
            }
        }

        Ok(())
    }

    /// Attempts to get the block root for the given `slot`.
    ///
    /// First, the `state` is used to see if the slot is within the distance of its historical
    /// lists. Then, the `chain` is used which will anchor the search at the given
    /// `justified_root`.
    fn get_block_root_at_slot<T: BeaconChainTypes>(
        state: &BeaconState<T::EthSpec>,
        chain: &BeaconChain<T>,
        justified_root: Hash256,
        slot: Slot,
    ) -> Result<Option<Hash256>> {
        match state.get_block_root(slot) {
            Ok(root) => Ok(Some(*root)),
            Err(_) => chain
                .get_ancestor_block_root(justified_root, slot)
                .map_err(Into::into),
        }
    }

    /// Calculate how far `slot` lies from the start of its epoch.
    fn compute_slots_since_epoch_start<T: BeaconChainTypes>(slot: Slot) -> u64 {
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        (slot - slot.epoch(slots_per_epoch).start_slot(slots_per_epoch)).as_u64()
    }
}

pub struct ForkChoice<T: BeaconChainTypes> {
    backend: ProtoArrayForkChoice,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    checkpoint_manager: RwLock<CheckpointManager>,
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes> PartialEq for ForkChoice<T> {
    /// This implementation ignores the `store`.
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.genesis_block_root == other.genesis_block_root
            && *self.checkpoint_manager.read() == *other.checkpoint_manager.read()
    }
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    /// Instantiate a new fork chooser.
    ///
    /// "Genesis" does not necessarily need to be the absolute genesis, it can be some finalized
    /// block.
    pub fn new(
        backend: ProtoArrayForkChoice,
        genesis_block_root: Hash256,
        genesis_state: &BeaconState<T::EthSpec>,
    ) -> Self {
        let genesis_checkpoint = CheckpointBalances {
            epoch: genesis_state.current_epoch(),
            root: genesis_block_root,
            balances: genesis_state.balances.clone().into(),
        };

        Self {
            backend,
            genesis_block_root,
            checkpoint_manager: RwLock::new(CheckpointManager::new(genesis_checkpoint.clone())),
            _phantom: PhantomData,
        }
    }

    /// Run the fork choice rule to determine the head.
    pub fn find_head(&self, chain: &BeaconChain<T>) -> Result<Hash256> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_FIND_HEAD_TIMES);

        let remove_alias = |root| {
            if root == Hash256::zero() {
                self.genesis_block_root
            } else {
                root
            }
        };

        let (justified_checkpoint, finalized_checkpoint) = {
            let mut jm = self.checkpoint_manager.write();
            jm.update(chain)?;

            (jm.current.justified.clone(), jm.current.finalized.clone())
        };

        let result = self
            .backend
            .find_head(
                justified_checkpoint.epoch,
                remove_alias(justified_checkpoint.root),
                finalized_checkpoint.epoch,
                &justified_checkpoint.balances,
            )
            .map_err(Into::into);

        metrics::stop_timer(timer);

        if FORK_CHOICE_DEBUGGING {
            if let Err(e) = &result {
                if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    let time = duration.as_millis();
                    if let Ok(mut file) = File::create(format!("/tmp/fork-choice-{}", time)) {
                        let _ = write!(file, "{:?}\n", e);
                        if let Ok(json) = self.backend.as_json() {
                            let _ = write!(file, "{}", json);
                        }
                    }
                }
            }
        }

        result
    }

    /// Process all attestations in the given `block`.
    ///
    /// Assumes the block (and therefore its attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        chain: &BeaconChain<T>,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
        block_root: Hash256,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);

        self.checkpoint_manager
            .write()
            .process_state(state, chain, &self.backend)?;
        self.checkpoint_manager.write().update(chain)?;

        // Note: we never count the block as a latest message, only attestations.
        for attestation in &block.body.attestations {
            // If the `data.beacon_block_root` block is not known to the fork choice, simply ignore
            // the vote.
            if self
                .backend
                .contains_block(&attestation.data.beacon_block_root)
            {
                self.process_attestation(state, attestation)?;
            }
        }

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        self.backend.process_block(
            block.slot,
            block_root,
            block.parent_root,
            state.current_justified_checkpoint.epoch,
            state.finalized_checkpoint.epoch,
        )?;

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Process an attestation which references `block` in `attestation.data.beacon_block_root`.
    ///
    /// Assumes the attestation is valid.
    pub fn process_attestation(
        &self,
        state: &BeaconState<T::EthSpec>,
        attestation: &Attestation<T::EthSpec>,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        let block_hash = attestation.data.beacon_block_root;

        // Ignore any attestations to the zero hash.
        //
        // This is an edge case that results from the spec aliasing the zero hash to the genesis
        // block. Attesters may attest to the zero hash if they have never seen a block.
        //
        // We have two options here:
        //
        //  1. Apply all zero-hash attestations to the zero hash.
        //  2. Ignore all attestations to the zero hash.
        //
        // (1) becomes weird once we hit finality and fork choice drops the genesis block. (2) is
        // fine because votes to the genesis block are not useful; all validators implicitly attest
        // to genesis just by being present in the chain.
        //
        // Additionally, don't add any block hash to fork choice unless we have imported the block.
        if block_hash != Hash256::zero() {
            let validator_indices =
                get_attesting_indices(state, &attestation.data, &attestation.aggregation_bits)?;

            for validator_index in validator_indices {
                self.backend.process_attestation(
                    validator_index,
                    block_hash,
                    attestation.data.target.epoch,
                )?;
            }
        }

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Returns the latest message for a given validator, if any.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Epoch)> {
        self.backend.latest_message(validator_index)
    }

    /// Trigger a prune on the underlying fork choice backend.
    pub fn prune(&self) -> Result<()> {
        let finalized_checkpoint = self.checkpoint_manager.read().current.finalized.clone();

        self.backend
            .maybe_prune(finalized_checkpoint.root)
            .map_err(Into::into)
    }

    /// Returns a `SszForkChoice` which contains the current state of `Self`.
    pub fn as_ssz_container(&self) -> SszForkChoice {
        SszForkChoice {
            genesis_block_root: self.genesis_block_root.clone(),
            checkpoint_manager: self.checkpoint_manager.read().clone(),
            backend_bytes: self.backend.as_bytes(),
        }
    }

    /// Instantiates `Self` from a prior `SszForkChoice`.
    ///
    /// The created `Self` will have the same state as the `Self` that created the `SszForkChoice`.
    pub fn from_ssz_container(ssz_container: SszForkChoice) -> Result<Self> {
        let backend = ProtoArrayForkChoice::from_bytes(&ssz_container.backend_bytes)?;

        Ok(Self {
            backend,
            genesis_block_root: ssz_container.genesis_block_root,
            checkpoint_manager: RwLock::new(ssz_container.checkpoint_manager),
            _phantom: PhantomData,
        })
    }
}

/// Helper struct that is used to encode/decode the state of the `ForkChoice` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct SszForkChoice {
    genesis_block_root: Hash256,
    checkpoint_manager: CheckpointManager,
    backend_bytes: Vec<u8>,
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Error {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Error {
        Error::StoreError(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::BackendError(e)
    }
}

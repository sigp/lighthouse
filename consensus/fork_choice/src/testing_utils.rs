use crate::ForkChoiceStore;
use std::collections::HashMap;
use types::{BeaconState, Checkpoint, Epoch, Eth1Data, EthSpec, Hash256, Slot};

pub struct StateBuilder<E: EthSpec> {
    state: BeaconState<E>,
}

impl<T: EthSpec> StateBuilder<T> {
    pub fn genesis() -> Self {
        let spec = T::default_spec();

        let state = BeaconState::new(
            0,
            Eth1Data {
                deposit_root: Hash256::zero(),
                deposit_count: 0,
                block_hash: Hash256::zero(),
            },
            &spec,
        );

        Self { state }
    }

    pub fn at_slot(mut self, slot: Slot) -> Self {
        self.state.slot = slot;

        let lowest_slot = slot
            .as_u64()
            .saturating_sub(T::slots_per_historical_root() as u64);

        for i in lowest_slot..slot.as_u64() {
            self.state
                .set_block_root(Slot::from(i), Hash256::from_low_u64_be(i))
                .unwrap()
        }

        self
    }

    pub fn ancestor_root_at_epoch(mut self, epoch: Epoch, root: Hash256) -> Self {
        self.state
            .set_block_root(epoch.start_slot(T::slots_per_epoch()), root)
            .unwrap();
        self
    }

    pub fn justified_at(mut self, epoch: Epoch) -> Self {
        self.state.current_justified_checkpoint.epoch = epoch;
        self.state.current_justified_checkpoint.root =
            Hash256::from_low_u64_be(epoch.start_slot(T::slots_per_epoch()).into());
        self
    }

    pub fn justified_root(mut self, root: Hash256) -> Self {
        self.state.current_justified_checkpoint.root = root;
        self
    }

    pub fn build(self) -> BeaconState<T> {
        self.state
    }
}

/// Provides a simple `ForkChoiceStore` implementation that can be used for unit-testing and
/// debugging.
///
/// ## Panics
///
/// Panics whenever it encounters an error.
#[derive(Debug)]
pub struct TestingStore<T: EthSpec> {
    states: HashMap<Hash256, BeaconState<T>>,
    pub current_time: Slot,
    previous_time: Slot,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    justified_balances: Vec<u64>,
    best_justified_checkpoint: Checkpoint,
    best_justified_balances: Option<Vec<u64>>,
}

impl<T: EthSpec> TestingStore<T> {
    pub fn from_genesis() -> Self {
        let genesis_state: BeaconState<T> = StateBuilder::genesis().build();

        Self {
            states: HashMap::new(),
            current_time: Slot::new(0),
            previous_time: Slot::new(0),
            finalized_checkpoint: genesis_state.finalized_checkpoint,
            justified_checkpoint: genesis_state.current_justified_checkpoint,
            justified_balances: genesis_state.balances.into(),
            best_justified_checkpoint: genesis_state.current_justified_checkpoint,
            best_justified_balances: None,
        }
    }

    pub fn from_state(state: BeaconState<T>) -> Self {
        let mut store = Self::from_genesis();

        store.current_time = state.slot;
        store.finalized_checkpoint = state.finalized_checkpoint;
        store.justified_checkpoint = state.current_justified_checkpoint;
        store.justified_balances = state.balances.clone().into();
        store.best_justified_checkpoint = state.current_justified_checkpoint;
        store.best_justified_balances = None;

        store
    }
}

impl<T: EthSpec> ForkChoiceStore<T> for TestingStore<T> {
    type Error = ();

    fn update_time(&mut self) -> Result<(), ()> {
        while self.previous_time < self.current_time {
            self.on_tick(self.previous_time + 1)?;
        }

        Ok(())
    }

    fn get_current_slot(&self) -> Slot {
        self.previous_time
    }

    fn set_current_slot(&mut self, slot: Slot) {
        self.previous_time = slot
    }

    fn set_justified_checkpoint_to_best_justified_checkpoint(&mut self) -> Result<(), ()> {
        if self.best_justified_balances.is_some() {
            self.justified_checkpoint = self.best_justified_checkpoint;
            self.justified_balances = self
                .best_justified_balances
                .take()
                .expect("protected by prior if statement");

            Ok(())
        } else {
            panic!("Best balances are uninitialized")
        }
    }

    fn justified_checkpoint(&self) -> &Checkpoint {
        &self.justified_checkpoint
    }

    fn justified_balances(&self) -> &[u64] {
        &self.justified_balances
    }

    fn best_justified_checkpoint(&self) -> &Checkpoint {
        &self.best_justified_checkpoint
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }

    fn set_finalized_checkpoint(&mut self, c: Checkpoint) {
        self.finalized_checkpoint = c
    }

    fn set_justified_checkpoint(&mut self, state: &BeaconState<T>) {
        self.justified_checkpoint = state.current_justified_checkpoint;
        self.justified_balances = state.balances.clone().into();
    }

    fn set_best_justified_checkpoint(&mut self, state: &BeaconState<T>) {
        self.best_justified_checkpoint = state.current_justified_checkpoint;
        self.best_justified_balances = Some(state.balances.clone().into());
    }

    fn ancestor_at_slot(
        &self,
        state: &BeaconState<T>,
        _root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Hash256, ()> {
        let root = match state.get_block_root(ancestor_slot) {
            Ok(root) => *root,
            Err(_) => todo!(),
        };

        Ok(root)
    }
}

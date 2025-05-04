use crate::StoreError as Error;
use crate::{HotColdDB, ItemStore};
use types::{BeaconState, EthSpec, Hash256, Slot};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct StoreMigrator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    store: Arc<HotColdDB<E, Hot, Cold>>,
    state: RwLock<MigratorState>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MigratorState {
    Idle,
    Migrating,
    Complete,
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> StoreMigrator<E, Hot, Cold> {
    pub fn new(store: Arc<HotColdDB<E, Hot, Cold>>) -> Self {
        Self {
            store,
            state: RwLock::new(MigratorState::Idle),
        }
    }

    pub fn start_migration(&self) -> Result<(), Error> {
        let mut state = self.state.write();
        if *state == MigratorState::Idle {
            *state = MigratorState::Migrating;
            Ok(())
        } else {
            Err(Error::MigrationAlreadyStarted)
        }
    }

    pub fn complete_migration(&self) -> Result<(), Error> {
        let mut state = self.state.write();
        if *state == MigratorState::Migrating {
            *state = MigratorState::Complete;
            Ok(())
        } else {
            Err(Error::MigrationNotStarted)
        }
    }

    pub fn get_state(&self) -> MigratorState {
        *self.state.read()
    }
} 
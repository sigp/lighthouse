use crate::StoreError as Error;
use types::{Hash256, Slot};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct PruningBuffer {
    pub blocks: HashMap<Hash256, Slot>,
    pub states: HashMap<Hash256, Slot>,
}

impl PruningBuffer {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            states: HashMap::new(),
        }
    }

    pub fn add_block(&mut self, root: Hash256, slot: Slot) -> Result<(), Error> {
        self.blocks.insert(root, slot);
        Ok(())
    }

    pub fn add_state(&mut self, root: Hash256, slot: Slot) -> Result<(), Error> {
        self.states.insert(root, slot);
        Ok(())
    }

    pub fn get_block_slot(&self, root: &Hash256) -> Option<Slot> {
        self.blocks.get(root).copied()
    }

    pub fn get_state_slot(&self, root: &Hash256) -> Option<Slot> {
        self.states.get(root).copied()
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.states.clear();
    }
} 
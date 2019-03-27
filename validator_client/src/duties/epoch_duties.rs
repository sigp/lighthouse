use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use types::{Epoch, PublicKey, Slot};

/// The type of work a validator is required to do in a given slot.
#[derive(Debug, Clone)]
pub struct WorkType {
    produce_block: bool,
    produce_attestation: bool,
}

/// The information required for a validator to propose and attest during some epoch.
///
/// Generally obtained from a Beacon Node, this information contains the validators canonical index
/// (their sequence in the global validator induction process) and the "shuffling" for that index
/// for some epoch.
#[derive(Debug, PartialEq, Clone, Copy, Default)]
pub struct EpochDuty {
    pub block_production_slot: Option<Slot>,
    pub attestation_slot: Slot,
    pub attestation_shard: u64,
    pub committee_index: u64,
}

impl EpochDuty {
    /// Returns `WorkType` if work needs to be done in the supplied `slot`
    pub fn is_work_slot(&self, slot: Slot) -> Option<WorkType> {
        // if validator is required to produce a slot return true
        let produce_block = match self.block_production_slot {
            Some(s) if s == slot => true,
            _ => false,
        };

        let mut produce_attestation = false;
        if self.attestation_slot == slot {
            produce_attestation = true;
        }

        if produce_block | produce_attestation {
            return Some(WorkType {
                produce_block,
                produce_attestation,
            });
        }
        None
    }
}
/// Maps a list of public keys (many validators) to an EpochDuty.
pub type EpochDuties = HashMap<PublicKey, Option<EpochDuty>>;

pub enum EpochDutiesMapError {
    Poisoned,
    UnknownEpoch,
    UnknownValidator,
}

/// Maps an `epoch` to some `EpochDuties` for a single validator.
pub struct EpochDutiesMap {
    pub slots_per_epoch: u64,
    pub map: HashMap<Epoch, EpochDuties>,
}

impl EpochDutiesMap {
    pub fn new(slots_per_epoch: u64) -> Self {
        Self {
            slots_per_epoch,
            map: HashMap::new(),
        }
    }
}

// Expose the hashmap methods
impl Deref for EpochDutiesMap {
    type Target = HashMap<Epoch, EpochDuties>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}
impl DerefMut for EpochDutiesMap {
    fn deref_mut(&mut self) -> &mut HashMap<Epoch, EpochDuties> {
        &mut self.map
    }
}

impl EpochDutiesMap {
    /// Checks if the validator has work to do.
    fn is_work_slot(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
    ) -> Result<Option<WorkType>, EpochDutiesMapError> {
        let epoch = slot.epoch(self.slots_per_epoch);

        let epoch_duties = self
            .map
            .get(&epoch)
            .ok_or_else(|| EpochDutiesMapError::UnknownEpoch)?;
        if let Some(epoch_duty) = epoch_duties.get(pubkey) {
            if let Some(duty) = epoch_duty {
                // Retrieves the duty for a validator at a given slot
                return Ok(duty.is_work_slot(slot));
            } else {
                // the validator isn't active
                return Ok(None);
            }
        } else {
            // validator isn't known
            return Err(EpochDutiesMapError::UnknownValidator);
        }
    }
}

// TODO: add tests.

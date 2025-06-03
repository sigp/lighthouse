use std::collections::{BTreeMap, HashMap};

use parking_lot::RwLock;

use crate::{ChainSpec, Epoch, EthSpec, Slot};
use ssz_derive::{Decode, Encode};

// TODO(pawan): think more carefully about this number
pub const EPOCHS_BETWEEN_VALIDATOR_CUSTODY_UPDATES: usize = 10;

/// Specifies the number of validators attached to this node.
#[derive(Debug, Copy, Encode, Decode, Clone)]
pub struct ValidatorCustodyCount {
    count: u64,
}

impl ValidatorCustodyCount {
    pub fn new(count: u64) -> Self {
        Self { count }
    }
}

impl std::ops::Deref for ValidatorCustodyCount {
    type Target = u64;
    fn deref(&self) -> &Self::Target {
        &self.count
    }
}

impl ValidatorCustodyCount {
    /// Number of columns/custody groups to custody based on the number of validators
    /// attached.
    pub fn custody_count(&self, spec: &ChainSpec) -> u64 {
        std::cmp::min(
            spec.number_of_columns as u64,
            spec.validator_custody_requirement + self.count - 1,
        )
    }
}

/// TODO(pawan): this currently just registers increases in validator count.
/// Does not handle decreasing validator counts
#[derive(Default, Debug)]
struct ValidatorRegistrations {
    /// Set of all validators that is registered to this node along with its effective balance
    /// in increments of `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP`
    validators: HashMap<usize, u64>,
    /// Maintains the number of unique validators that hit the subscriptions endpoint each
    /// epoch where the validator count changed from the previous epoch.
    ///
    /// If the count is same between subsequent epochs, then the later epoch values aren't stored
    /// to save space.
    epoch_validators: BTreeMap<Epoch, u64>,
}

impl ValidatorRegistrations {
    /// Returns the validator count at the latest epoch for the custody requirement.
    pub fn latest_validator_count_for_custody(&self) -> Option<u64> {
        self.epoch_validators.last_key_value().map(|(_, v)| *v)
    }

    /// Returns the total validator count based on the effective balance.
    ///
    /// Note: Each `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` effectively contributes one unit of weight.
    pub fn custody_requirement(&self) -> u64 {
        self.validators.values().sum()
    }

    /// Returns the latest epoch at which the validator count changed.
    #[allow(dead_code)]
    pub fn latest_epoch(&self) -> Option<Epoch> {
        self.epoch_validators.last_key_value().map(|(k, _)| *k)
    }

    /// Register a new validator index and updates the list of validators if required.
    pub fn register_validator<E: EthSpec>(
        &mut self,
        validator_index: usize,
        effective_balance: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) {
        let epoch = slot.epoch(E::slots_per_epoch());
        // This is the "weight" of the validator based on the effective balance
        let num_validators_for_effective_balance =
            effective_balance / spec.balance_per_additional_custody_group;
        self.validators
            .insert(validator_index, num_validators_for_effective_balance);
        let count_at_epoch = self.custody_requirement();
        // If registering the new validator increased the validator count, then
        // add a new entry for the current epoch
        if Some(count_at_epoch) != self.latest_validator_count_for_custody() {
            self.epoch_validators
                .entry(epoch)
                .and_modify(|old_count| *old_count = count_at_epoch)
                .or_insert(count_at_epoch);
        }
    }
}

#[derive(Debug)]
pub struct CustodyContext {
    /// Columns to be custodied based on number of validators
    /// that is attached to this node.
    ///
    /// This is the number that we use to compute the custody count value that
    /// we advertise to our peers in the metadata and enr values.
    advertised_validator_custody: RwLock<ValidatorCustodyCount>,
    /// This is the validator count that we use to compute the number of columns we need to
    /// sample at head (while syncing or when receiving gossip).
    validator_custody_at_head: RwLock<ValidatorCustodyCount>,
    /// Is the node run as a supernode based on current cli parameters.
    pub current_is_supernode: bool,
    /// The persisted value for `is_supernode` based on the previous run of this node.
    ///
    /// Note: We require this value because if a user restarts the node with a higher cli custody
    /// count value than in the previous run, then we should continue advertising the custody
    /// count based on the old value than the new one since we haven't backfilled the required
    /// columns.
    persisted_is_supernode: bool,
    /// Updates to the number of validators that is attached to this node
    /// over a given time duration.
    /// TODO(pawan): make this a constant sized queue.
    /// might not need this with epoch_validators
    validator_custody_updates: Vec<(Epoch, usize)>,
    /// Maintains all the validators that this node is connected to currently
    validator_registrations: RwLock<ValidatorRegistrations>,
}

impl CustodyContext {
    /// Create a new custody default custody context object when no persisted object
    /// exists.
    ///
    /// The `is_supernode` value is based on current cli parameters.
    pub fn new(is_supernode: bool) -> Self {
        Self {
            advertised_validator_custody: RwLock::new(ValidatorCustodyCount::new(0)),
            validator_custody_at_head: RwLock::new(ValidatorCustodyCount::new(0)),
            current_is_supernode: is_supernode,
            persisted_is_supernode: is_supernode,
            validator_custody_updates: vec![],
            validator_registrations: Default::default(),
        }
    }

    /// Deserialize a `CustodyContext` from SSZ bytes.
    pub fn new_from_persisted_custody_context(
        ssz_context: CustodyContextSsz,
        is_supernode: bool,
    ) -> Self {
        CustodyContext {
            advertised_validator_custody: RwLock::new(ssz_context.advertised_validator_custody),
            validator_custody_at_head: RwLock::new(ssz_context.validator_custody_at_head),
            current_is_supernode: is_supernode,
            persisted_is_supernode: ssz_context.persisted_is_supernode,
            validator_custody_updates: ssz_context.validator_custody_updates,
            validator_registrations: Default::default(),
        }
    }

    /// Register a new validator index and updates the list of validators if required.
    pub fn register_validator<E: EthSpec>(
        &self,
        validator_index: usize,
        effective_balance: u64,
        slot: Slot,
        spec: &ChainSpec,
    ) {
        self.validator_registrations
            .write()
            .register_validator::<E>(validator_index, effective_balance, slot, spec)
    }

    /// The custody count that we advertise to our peers in our metadata and
    /// enr values.
    pub fn advertised_custody_column_count(&self, spec: &ChainSpec) -> u64 {
        if self.persisted_is_supernode {
            return spec.number_of_columns;
        }
        let advertised_validator_custody = self.advertised_validator_custody.read().count;
        if advertised_validator_custody > 0 {
            std::cmp::min(
                spec.validator_custody_requirement + advertised_validator_custody - 1
                    + spec.custody_requirement,
                spec.number_of_columns,
            )
        } else {
            spec.custody_requirement
        }
    }

    /// The custody count that we use to custody columns currently.
    ///
    /// This function should be called when figuring out how many columns we
    /// need to custody when receiving blocks over gossip/rpc or during sync.
    pub fn head_custody_count(&self, spec: &ChainSpec) -> u64 {
        if self.current_is_supernode {
            return spec.number_of_columns;
        }
        let custody_at_head = self.validator_custody_at_head.read().count;
        if custody_at_head > 0 {
            std::cmp::min(
                spec.validator_custody_requirement + custody_at_head - 1 + spec.custody_requirement,
                spec.number_of_columns,
            )
        } else {
            spec.custody_requirement
        }
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct CustodyContextSsz {
    advertised_validator_custody: ValidatorCustodyCount,
    validator_custody_at_head: ValidatorCustodyCount,
    persisted_is_supernode: bool,
    validator_custody_updates: Vec<(Epoch, usize)>,
}

impl From<&CustodyContext> for CustodyContextSsz {
    fn from(context: &CustodyContext) -> Self {
        CustodyContextSsz {
            advertised_validator_custody: context.advertised_validator_custody.read().clone(),
            validator_custody_at_head: context.validator_custody_at_head.read().clone(),
            persisted_is_supernode: context.persisted_is_supernode,
            validator_custody_updates: context.validator_custody_updates.clone(),
        }
    }
}

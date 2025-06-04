use std::collections::{BTreeMap, HashMap};

use parking_lot::RwLock;

use crate::{ChainSpec, Epoch, EthSpec, Slot};
use ssz_derive::{Decode, Encode};

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
    ///
    /// This should be equivalent to the current `validator_custody_at_head`.
    pub fn latest_validator_count_for_custody(&self) -> Option<u64> {
        self.epoch_validators.last_key_value().map(|(_, v)| *v)
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

        // Each `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` effectively contributes one unit of "weight".
        let count_at_epoch = self.validators.values().sum();

        // If registering the new validator increased the validator count, then
        // add a new entry for the current epoch
        if Some(count_at_epoch) != self.latest_validator_count_for_custody() {
            self.epoch_validators
                .entry(epoch)
                .and_modify(|old_count| *old_count = count_at_epoch)
                .or_insert(count_at_epoch);
        }
        tracing::debug!(
            %epoch,
            validator_count = count_at_epoch,
            "Registered validators"
        );
    }
}

/// Given the `count` of validators, return the custody requirement based on
/// the spec parameters.
///
/// Note: a validator here represents a unit of 32 eth effective_balance
/// equivalent to `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP`.
///
/// For e.g. a validator with eb 32 eth is 1 unit.
/// a validator with eb 65 eth is 65 // 32 = 2 units.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/validator.md#validator-custody
fn get_validators_custody_requirement(count: u64, spec: &ChainSpec) -> u64 {
    std::cmp::min(
        std::cmp::max(count, spec.validator_custody_requirement),
        spec.number_of_custody_groups,
    )
}

/// Contains all the information the node requires to calculate the 
/// number of columns to be custodied when checking for DA.
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
            validator_registrations: Default::default(),
        }
    }

    /// Register a new validator index and updates the list of validators if required.
    ///
    /// Also modifies the internal structures if the validator custody has changed to
    /// update the `custody_column_count`.
    pub fn register_validator<E: EthSpec>(
        &self,
        validators_and_balance: Vec<(usize, u64)>,
        slot: Slot,
        spec: &ChainSpec,
    ) {
        // Only do the registrations once per epoch
        if slot % E::slots_per_epoch() != 0 {
            return;
        }

        let mut registrations = self.validator_registrations.write();
        for (validator_index, effective_balance) in validators_and_balance {
            registrations.register_validator::<E>(validator_index, effective_balance, slot, spec);
        }

        // Completed registrations, now check if the cgc has changed
        let mut validator_custody_at_head = self.validator_custody_at_head.write();
        let Some(new_validator_custody) = registrations.latest_validator_count_for_custody() else {
            return;
        };

        // Update the current validator custody value if the validator registration changes the number of
        // validators
        if new_validator_custody != validator_custody_at_head.count {
            tracing::debug!(
                old_count = validator_custody_at_head.count,
                new_count = new_validator_custody,
                "Validator count at head updated"
            );
            *validator_custody_at_head = ValidatorCustodyCount {
                count: new_validator_custody,
            };
        }
    }

    /// The custody count that we advertise to our peers in our metadata and
    /// enr values.
    pub fn advertised_custody_column_count(&self, spec: &ChainSpec) -> u64 {
        if self.persisted_is_supernode {
            return spec.number_of_columns;
        }
        let advertised_validator_custody = self.advertised_validator_custody.read().count;
        if advertised_validator_custody > 0 {
            get_validators_custody_requirement(advertised_validator_custody, spec)
                + spec.custody_requirement
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
            get_validators_custody_requirement(custody_at_head, spec) + spec.custody_requirement
        } else {
            spec.custody_requirement
        }
    }
}

/// The custody information that gets persisted across runs.
#[derive(Debug, Encode, Decode, Clone)]
pub struct CustodyContextSsz {
    advertised_validator_custody: ValidatorCustodyCount,
    validator_custody_at_head: ValidatorCustodyCount,
    persisted_is_supernode: bool,
}

impl From<&CustodyContext> for CustodyContextSsz {
    fn from(context: &CustodyContext) -> Self {
        CustodyContextSsz {
            advertised_validator_custody: context.advertised_validator_custody.read().clone(),
            validator_custody_at_head: context.validator_custody_at_head.read().clone(),
            persisted_is_supernode: context.persisted_is_supernode,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MainnetEthSpec;

    use super::*;

    type E = MainnetEthSpec;

    #[test]
    fn no_validators() {
        // supernode without validators
        let custody_context = CustodyContext::new(true);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.number_of_columns
        );
        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.number_of_columns
        );
    }

    #[test]
    fn fullnode() {
        // fullnode without validators
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.custody_requirement,
            "head custody count should be minimum spec custody requirement"
        );
        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.custody_requirement,
            "advertised custody count should be minimum spec custody requirement"
        );

        // add 1 validator
        custody_context.register_validator::<E>(vec![(0, 32_000_000_000)], Slot::new(0), &spec);

        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement,
            "head custody count should increase with 1 validator"
        );

        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );

        // add 7 more validators to reach `validator_custody_requirement`
        custody_context.register_validator::<E>(
            vec![
                (1, 32_000_000_000),
                (2, 32_000_000_000),
                (3, 32_000_000_000),
                (4, 32_000_000_000),
                (5, 32_000_000_000),
                (6, 32_000_000_000),
                (7, 32_000_000_000),
            ],
            Slot::new(0),
            &spec,
        );

        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement,
            "head custody count should should be same as with 1 validator"
        );

        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );

        // adding 1 more validator should increase the custody count
        custody_context.register_validator::<E>(vec![(8, 32_000_000_000)], Slot::new(0), &spec);
        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement + 1,
            "head custody count should increase by 1"
        );

        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );

        // update effective balance for some validators.
        // validator count should increase by 3
        custody_context.register_validator::<E>(
            vec![
                (1, 96_000_000_000),
                (2, 65_000_000_000),
                (3, 32_000_000_000),
                (4, 32_000_000_000),
                (5, 32_000_000_000),
                (6, 32_000_000_000),
                (7, 32_000_000_000),
                (8, 32_000_000_000),
            ],
            Slot::new(0),
            &spec,
        );

        assert_eq!(
            custody_context.head_custody_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement + 4,
            "head custody count should increase by 3"
        );

        assert_eq!(
            custody_context.advertised_custody_column_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );
    }
}

use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::RwLock;

use ssz_derive::{Decode, Encode};
use types::{ChainSpec, Epoch, EthSpec, Slot};

/// TODO(pawan): this currently just registers increases in validator count.
/// Does not handle decreasing validator counts
#[derive(Default, Debug)]
struct ValidatorRegistrations {
    /// Set of all validators that is registered to this node along with its effective balance
    ///
    /// Key is validator index and value is effective_balance.
    validators: HashMap<usize, u64>,
    /// Maintains the validator custody requirement at a given epoch.
    ///
    /// Note: Only stores the epoch value when there's a change in custody requirement.
    /// So if epoch 10 and 11 has the same custody requirement, only 10 is stored.
    /// This map is never pruned, because currently we never decrease custody requirement, so this
    /// map size is contained at 128.
    epoch_validator_custody_requirements: BTreeMap<Epoch, u64>,
}

impl ValidatorRegistrations {
    /// Returns the validator custody requirement at the latest epoch.
    pub fn latest_validator_custody_requirement(&self) -> Option<u64> {
        self.epoch_validator_custody_requirements
            .last_key_value()
            .map(|(_, v)| *v)
    }

    /// Returns the latest epoch at which the validator count changed.
    #[allow(dead_code)]
    pub fn latest_epoch(&self) -> Option<Epoch> {
        self.epoch_validator_custody_requirements
            .last_key_value()
            .map(|(k, _)| *k)
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
        self.validators.insert(validator_index, effective_balance);

        // Each `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` effectively contributes one unit of "weight".
        let validator_custody_units =
            self.validators.values().sum::<u64>() / spec.balance_per_additional_custody_group;
        let validator_custody_requirement =
            get_validators_custody_requirement(validator_custody_units, spec);

        // If registering the new validator increased the total validator "units", then
        // add a new entry for the current epoch
        if Some(validator_custody_requirement) != self.latest_validator_custody_requirement() {
            self.epoch_validator_custody_requirements
                .entry(epoch)
                .and_modify(|old_custody| *old_custody = validator_custody_requirement)
                .or_insert(validator_custody_requirement);
        }
        tracing::debug!(
            %epoch,
            validator_custody_units,
            validator_custody_requirement,
            "Registered validators"
        );
    }
}

/// Given the `validator_custody_units`, return the custody requirement based on
/// the spec parameters.
///
/// Note: a `validator_custody_units` here represents the number of 32 eth effective_balance
/// equivalent to `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP`.
///
/// For e.g. a validator with eb 32 eth is 1 unit.
/// a validator with eb 65 eth is 65 // 32 = 2 units.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/validator.md#validator-custody
fn get_validators_custody_requirement(validator_custody_units: u64, spec: &ChainSpec) -> u64 {
    std::cmp::min(
        std::cmp::max(validator_custody_units, spec.validator_custody_requirement),
        spec.number_of_custody_groups,
    )
}

/// Contains all the information the node requires to calculate the
/// number of columns to be custodied when checking for DA.
#[derive(Debug)]
pub struct CustodyContext {
    /// The Number of custody groups required based on the number of validators
    /// that is attached to this node.
    ///
    /// This is the number that we use to compute the custody group count that
    /// we require for data availability check, and we use to advertise to our peers in the metadata
    /// and enr values.
    validator_custody_count: AtomicU64,
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
            validator_custody_count: AtomicU64::new(0),
            current_is_supernode: is_supernode,
            persisted_is_supernode: is_supernode,
            validator_registrations: Default::default(),
        }
    }

    pub fn new_from_persisted_custody_context(
        ssz_context: CustodyContextSsz,
        is_supernode: bool,
    ) -> Self {
        CustodyContext {
            validator_custody_count: AtomicU64::new(ssz_context.validator_custody_at_head),
            current_is_supernode: is_supernode,
            persisted_is_supernode: ssz_context.persisted_is_supernode,
            validator_registrations: Default::default(),
        }
    }

    /// Register a new validator index and updates the list of validators if required.
    ///
    /// Also modifies the internal structures if the validator custody has changed to
    /// update the `custody_column_count`.
    ///
    /// Returns `Some` along with the updated custody group count if it has changed, otherwise returns `None`.
    pub fn register_validators<E: EthSpec>(
        &self,
        validators_and_balance: Vec<(usize, u64)>,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Option<CustodyCountChanged> {
        let mut registrations = self.validator_registrations.write();
        for (validator_index, effective_balance) in validators_and_balance {
            registrations.register_validator::<E>(validator_index, effective_balance, slot, spec);
        }

        // Completed registrations, now check if the validator custody requirement has changed
        let Some(new_validator_custody) = registrations.latest_validator_custody_requirement()
        else {
            return None;
        };

        let current_cgc = self.custody_group_count(spec);
        let validator_custody_count_at_head = self.validator_custody_count.load(Ordering::Relaxed);

        if new_validator_custody != validator_custody_count_at_head {
            tracing::debug!(
                old_count = validator_custody_count_at_head,
                new_count = new_validator_custody,
                "Validator count at head updated"
            );
            self.validator_custody_count
                .store(new_validator_custody, Ordering::Relaxed);

            let updated_cgc = self.custody_group_count(spec);
            // Send the message to network only if there are more columns subnets to subscribe to
            if updated_cgc > current_cgc {
                tracing::debug!(
                    old_cgc = current_cgc,
                    updated_cgc,
                    "Custody group count updated"
                );
                return Some(CustodyCountChanged {
                    new_custody_group_count: updated_cgc,
                    sampling_count: self.sampling_count(spec),
                });
            }
        }

        None
    }

    /// The custody count that we use to custody columns currently.
    ///
    /// This function should be called when figuring out how many columns we
    /// need to custody when receiving blocks over gossip/rpc or during sync.
    pub(crate) fn custody_group_count(&self, spec: &ChainSpec) -> u64 {
        if self.current_is_supernode {
            return spec.number_of_custody_groups;
        }
        let validator_custody_count_at_head = self.validator_custody_count.load(Ordering::Relaxed);

        // If there are no validators, return the minimum custody_requirement
        if validator_custody_count_at_head > 0 {
            validator_custody_count_at_head
        } else {
            spec.custody_requirement
        }
    }

    /// Returns the count of custody columns this node must sample for block import.
    pub fn sampling_count(&self, spec: &ChainSpec) -> u64 {
        // This only panics if the chain spec contains invalid values
        spec.sampling_size(self.custody_group_count(spec))
            .expect("should compute node sampling size from valid chain spec")
    }
}

/// The custody count changed because of a change in the
/// number of validators being managed.
pub struct CustodyCountChanged {
    pub new_custody_group_count: u64,
    pub sampling_count: u64,
}

/// The custody information that gets persisted across runs.
#[derive(Debug, Encode, Decode, Clone)]
pub struct CustodyContextSsz {
    validator_custody_at_head: u64,
    persisted_is_supernode: bool,
}

impl From<&CustodyContext> for CustodyContextSsz {
    fn from(context: &CustodyContext) -> Self {
        CustodyContextSsz {
            validator_custody_at_head: context.validator_custody_count.load(Ordering::Relaxed),
            persisted_is_supernode: context.persisted_is_supernode,
        }
    }
}

#[cfg(test)]
mod tests {
    use types::MainnetEthSpec;

    use super::*;

    type E = MainnetEthSpec;

    #[test]
    fn no_validators_supernode_default() {
        let custody_context = CustodyContext::new(true);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.custody_group_count(&spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn no_validators_fullnode_default() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.custody_group_count(&spec),
            spec.custody_requirement,
            "head custody count should be minimum spec custody requirement"
        );
    }

    #[test]
    fn register_single_validator_should_update_cgc() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let bal_per_additional_group = spec.balance_per_additional_custody_group;
        let min_val_custody_requirement = spec.validator_custody_requirement;
        // One single node increases its balance over 3 epochs.
        let validators_and_expected_cgc = vec![
            (
                vec![(0, bal_per_additional_group)],
                min_val_custody_requirement,
            ),
            (
                vec![(0, 8 * bal_per_additional_group)],
                min_val_custody_requirement,
            ),
            (vec![(0, 10 * bal_per_additional_group)], 10),
        ];

        register_validators_and_assert_cgc(custody_context, validators_and_expected_cgc, &spec);
    }

    #[test]
    fn register_multiple_validators_should_update_cgc() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let bal_per_additional_group = spec.balance_per_additional_custody_group;
        let min_val_custody_requirement = spec.validator_custody_requirement;
        // Add 3 validators over 3 epochs.
        let validators_and_expected_cgc = vec![
            (
                vec![(0, bal_per_additional_group)],
                min_val_custody_requirement,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                ],
                min_val_custody_requirement,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                    (2, 2 * bal_per_additional_group),
                ],
                10,
            ),
        ];

        register_validators_and_assert_cgc(custody_context, validators_and_expected_cgc, &spec);
    }

    #[test]
    fn register_validators_should_not_update_cgc_for_supernode() {
        let custody_context = CustodyContext::new(true);
        let spec = E::default_spec();
        let bal_per_additional_group = spec.balance_per_additional_custody_group;

        // Add 3 validators over 3 epochs.
        let validators_and_expected_cgc = vec![
            (
                vec![(0, bal_per_additional_group)],
                spec.number_of_custody_groups,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                ],
                spec.number_of_custody_groups,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                    (2, 2 * bal_per_additional_group),
                ],
                spec.number_of_custody_groups,
            ),
        ];

        register_validators_and_assert_cgc(custody_context, validators_and_expected_cgc, &spec);
    }

    /// Update validator every epoch and assert cgc against expected values.
    fn register_validators_and_assert_cgc(
        custody_context: CustodyContext,
        validators_and_expected_cgc: Vec<(Vec<(usize, u64)>, u64)>,
        spec: &ChainSpec,
    ) {
        for (idx, (validators_and_balance, expected_cgc)) in
            validators_and_expected_cgc.into_iter().enumerate()
        {
            let epoch = Epoch::new(idx as u64);
            custody_context.register_validators::<E>(
                validators_and_balance,
                epoch.start_slot(E::slots_per_epoch()),
                spec,
            );

            assert_eq!(custody_context.custody_group_count(spec), expected_cgc);
        }
    }
}

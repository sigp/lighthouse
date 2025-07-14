use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::RwLock;

use ssz_derive::{Decode, Encode};
use types::{ChainSpec, Epoch, EthSpec, Slot};

/// A delay before making the CGC change effective to the data availability checker.
const CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS: u64 = 30;

/// Number of slots after which a validator's registration is removed if it has not re-registered.
const VALIDATOR_REGISTRATION_EXPIRY_SLOTS: Slot = Slot::new(256);

type ValidatorsAndBalances = Vec<(usize, u64)>;
type SlotAndEffectiveBalance = (Slot, u64);

/// This currently just registers increases in validator count.
/// Does not handle decreasing validator counts
#[derive(Default, Debug)]
struct ValidatorRegistrations {
    /// Set of all validators that is registered to this node along with its effective balance
    ///
    /// Key is validator index and value is effective_balance.
    validators: HashMap<usize, SlotAndEffectiveBalance>,
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
    fn latest_validator_custody_requirement(&self) -> Option<u64> {
        self.epoch_validator_custody_requirements
            .last_key_value()
            .map(|(_, v)| *v)
    }

    /// Lookup the active custody requirement at the given epoch.
    fn custody_requirement_at_epoch(&self, epoch: Epoch) -> Option<u64> {
        self.epoch_validator_custody_requirements
            .range(..=epoch)
            .last()
            .map(|(_, custody_count)| *custody_count)
    }

    /// Register a new validator index and updates the list of validators if required.
    /// Returns `Some((effective_epoch, new_cgc))` if the registration results in a CGC update.
    pub(crate) fn register_validators<E: EthSpec>(
        &mut self,
        validators_and_balance: ValidatorsAndBalances,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Option<(Epoch, u64)> {
        for (validator_index, effective_balance) in validators_and_balance {
            self.validators
                .insert(validator_index, (current_slot, effective_balance));
        }

        // Drop validators that haven't re-registered with the node for `VALIDATOR_REGISTRATION_EXPIRY_SLOTS`.
        self.validators
            .retain(|_, (slot, _)| *slot >= current_slot - VALIDATOR_REGISTRATION_EXPIRY_SLOTS);

        // Each `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` effectively contributes one unit of "weight".
        let validator_custody_units = self.validators.values().map(|(_, eb)| eb).sum::<u64>()
            / spec.balance_per_additional_custody_group;
        let validator_custody_requirement =
            get_validators_custody_requirement(validator_custody_units, spec);

        tracing::debug!(
            validator_custody_units,
            validator_custody_requirement,
            "Registered validators"
        );

        // If registering the new validator increased the total validator "units", then
        // add a new entry for the current epoch
        if Some(validator_custody_requirement) > self.latest_validator_custody_requirement() {
            // Apply the change from the next epoch after adding some delay buffer to ensure
            // the node has enough time to subscribe to subnets etc, and to avoid having
            // inconsistent column counts within an epoch.
            let effective_delay_slots =
                CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS / spec.seconds_per_slot;
            let effective_epoch =
                (current_slot + effective_delay_slots).epoch(E::slots_per_epoch()) + 1;
            self.epoch_validator_custody_requirements
                .entry(effective_epoch)
                .and_modify(|old_custody| *old_custody = validator_custody_requirement)
                .or_insert(validator_custody_requirement);
            Some((effective_epoch, validator_custody_requirement))
        } else {
            None
        }
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
            validator_registrations: RwLock::new(ValidatorRegistrations {
                validators: Default::default(),
                epoch_validator_custody_requirements: ssz_context
                    .epoch_validator_custody_requirements
                    .into_iter()
                    .collect(),
            }),
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
        validators_and_balance: ValidatorsAndBalances,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Option<CustodyCountChanged> {
        let Some((effective_epoch, new_validator_custody)) = self
            .validator_registrations
            .write()
            .register_validators::<E>(validators_and_balance, current_slot, spec)
        else {
            return None;
        };

        let current_cgc = self.custody_group_count_at_head(spec);
        let validator_custody_count_at_head = self.validator_custody_count.load(Ordering::Relaxed);

        if new_validator_custody != validator_custody_count_at_head {
            tracing::debug!(
                old_count = validator_custody_count_at_head,
                new_count = new_validator_custody,
                "Validator count at head updated"
            );
            self.validator_custody_count
                .store(new_validator_custody, Ordering::Relaxed);

            let updated_cgc = self.custody_group_count_at_head(spec);
            // Send the message to network only if there are more columns subnets to subscribe to
            if updated_cgc > current_cgc {
                tracing::debug!(
                    old_cgc = current_cgc,
                    updated_cgc,
                    "Custody group count updated"
                );
                return Some(CustodyCountChanged {
                    new_custody_group_count: updated_cgc,
                    sampling_count: self
                        .num_of_custody_groups_to_sample(Some(effective_epoch), spec),
                });
            }
        }

        None
    }

    /// This function is used to determine the custody group count at head ONLY.
    /// Do NOT use this directly for data availability check, use `self.sampling_size` instead as
    /// CGC can change over epochs.
    pub fn custody_group_count_at_head(&self, spec: &ChainSpec) -> u64 {
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

    /// This function is used to determine the custody group count at a given epoch.
    ///
    /// This differs from the number of custody groups sampled per slot, as the spec requires a
    /// minimum sampling size which may exceed the custody group count (CGC).
    ///
    /// See also: [`Self::num_of_custody_groups_to_sample`].
    fn custody_group_count_at_epoch(&self, epoch_opt: Option<Epoch>, spec: &ChainSpec) -> u64 {
        let custody_group_count = if self.current_is_supernode {
            spec.number_of_custody_groups
        } else if let Some(epoch) = epoch_opt {
            self.validator_registrations
                .read()
                .custody_requirement_at_epoch(epoch)
                .unwrap_or(spec.custody_requirement)
        } else {
            self.custody_group_count_at_head(spec)
        };
        custody_group_count
    }

    /// Returns the count of custody groups this node must _sample_ for a block at `epoch` to import.
    /// If an `epoch` is not specified, returns the *current* validator custody requirement.
    pub fn num_of_custody_groups_to_sample(
        &self,
        epoch_opt: Option<Epoch>,
        spec: &ChainSpec,
    ) -> u64 {
        let custody_group_count = self.custody_group_count_at_epoch(epoch_opt, spec);
        spec.sampling_size_custody_groups(custody_group_count)
            .expect("should compute node sampling size from valid chain spec")
    }

    /// Returns the count of columns this node must _sample_ for a block at `epoch` to import.
    /// If an `epoch` is not specified, returns the *current* validator custody requirement.
    pub fn num_of_data_columns_to_sample(&self, epoch_opt: Option<Epoch>, spec: &ChainSpec) -> u64 {
        let custody_group_count = self.custody_group_count_at_epoch(epoch_opt, spec);
        spec.sampling_size_columns(custody_group_count)
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
    pub validator_custody_at_head: u64,
    pub persisted_is_supernode: bool,
    pub epoch_validator_custody_requirements: Vec<(Epoch, u64)>,
}

impl From<&CustodyContext> for CustodyContextSsz {
    fn from(context: &CustodyContext) -> Self {
        CustodyContextSsz {
            validator_custody_at_head: context.validator_custody_count.load(Ordering::Relaxed),
            persisted_is_supernode: context.persisted_is_supernode,
            epoch_validator_custody_requirements: context
                .validator_registrations
                .read()
                .epoch_validator_custody_requirements
                .iter()
                .map(|(epoch, count)| (*epoch, *count))
                .collect(),
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
            custody_context.custody_group_count_at_head(&spec),
            spec.number_of_custody_groups
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(None, &spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn no_validators_fullnode_default() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            spec.custody_requirement,
            "head custody count should be minimum spec custody requirement"
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(None, &spec),
            spec.samples_per_slot
        );
    }

    #[test]
    fn register_single_validator_should_update_cgc() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let bal_per_additional_group = spec.balance_per_additional_custody_group;
        let min_val_custody_requirement = spec.validator_custody_requirement;
        // One single node increases its balance over 3 epochs.
        let validators_and_expected_cgc_change = vec![
            (
                vec![(0, bal_per_additional_group)],
                Some(min_val_custody_requirement),
            ),
            // No CGC change at 8 custody units, as it's the minimum requirement
            (vec![(0, 8 * bal_per_additional_group)], None),
            (vec![(0, 10 * bal_per_additional_group)], Some(10)),
        ];

        register_validators_and_assert_cgc(
            &custody_context,
            validators_and_expected_cgc_change,
            &spec,
        );
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
                Some(min_val_custody_requirement),
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                ],
                // No CGC change at 8 custody units, as it's the minimum requirement
                None,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                    (2, 2 * bal_per_additional_group),
                ],
                Some(10),
            ),
        ];

        register_validators_and_assert_cgc(&custody_context, validators_and_expected_cgc, &spec);
    }

    #[test]
    fn register_validators_should_not_update_cgc_for_supernode() {
        let custody_context = CustodyContext::new(true);
        let spec = E::default_spec();
        let bal_per_additional_group = spec.balance_per_additional_custody_group;

        // Add 3 validators over 3 epochs.
        let validators_and_expected_cgc = vec![
            (vec![(0, bal_per_additional_group)], None),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                ],
                None,
            ),
            (
                vec![
                    (0, bal_per_additional_group),
                    (1, 7 * bal_per_additional_group),
                    (2, 2 * bal_per_additional_group),
                ],
                None,
            ),
        ];

        register_validators_and_assert_cgc(&custody_context, validators_and_expected_cgc, &spec);
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(None, &spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn cgc_change_should_be_effective_to_sampling_after_delay() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let current_slot = Slot::new(10);
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let default_sampling_size = custody_context.num_of_custody_groups_to_sample(None, &spec);
        let validator_custody_units = 10;

        let _cgc_changed = custody_context.register_validators::<E>(
            vec![(
                0,
                validator_custody_units * spec.balance_per_additional_custody_group,
            )],
            current_slot,
            &spec,
        );

        // CGC update is not applied for `current_epoch`.
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Some(current_epoch), &spec),
            default_sampling_size
        );
        // CGC update is applied for the next epoch.
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Some(current_epoch + 1), &spec),
            validator_custody_units
        );
    }

    #[test]
    fn validator_dropped_after_no_registrations_within_expiry_should_not_reduce_cgc() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let current_slot = Slot::new(10);
        let val_custody_units_1 = 10;
        let val_custody_units_2 = 5;

        // GIVEN val_1 and val_2 registered at `current_slot`
        let _ = custody_context.register_validators::<E>(
            vec![
                (
                    1,
                    val_custody_units_1 * spec.balance_per_additional_custody_group,
                ),
                (
                    2,
                    val_custody_units_2 * spec.balance_per_additional_custody_group,
                ),
            ],
            current_slot,
            &spec,
        );

        // WHEN val_1 re-registered, but val_2 did not re-register after `VALIDATOR_REGISTRATION_EXPIRY_SLOTS + 1` slots
        let cgc_changed_opt = custody_context.register_validators::<E>(
            vec![(
                1,
                val_custody_units_1 * spec.balance_per_additional_custody_group,
            )],
            current_slot + VALIDATOR_REGISTRATION_EXPIRY_SLOTS + 1,
            &spec,
        );

        // THEN the reduction from dropping val_2 balance should NOT result in a CGC reduction
        assert!(cgc_changed_opt.is_none(), "CGC should remain unchanged");
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            val_custody_units_1 + val_custody_units_2
        )
    }

    #[test]
    fn validator_dropped_after_no_registrations_within_expiry() {
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        let current_slot = Slot::new(10);
        let val_custody_units_1 = 10;
        let val_custody_units_2 = 5;
        let val_custody_units_3 = 6;

        // GIVEN val_1 and val_2 registered at `current_slot`
        let _ = custody_context.register_validators::<E>(
            vec![
                (
                    1,
                    val_custody_units_1 * spec.balance_per_additional_custody_group,
                ),
                (
                    2,
                    val_custody_units_2 * spec.balance_per_additional_custody_group,
                ),
            ],
            current_slot,
            &spec,
        );

        // WHEN val_1 and val_3 registered, but val_3 did not re-register after `VALIDATOR_REGISTRATION_EXPIRY_SLOTS + 1` slots
        let cgc_changed = custody_context.register_validators::<E>(
            vec![
                (
                    1,
                    val_custody_units_1 * spec.balance_per_additional_custody_group,
                ),
                (
                    3,
                    val_custody_units_3 * spec.balance_per_additional_custody_group,
                ),
            ],
            current_slot + VALIDATOR_REGISTRATION_EXPIRY_SLOTS + 1,
            &spec,
        );

        // THEN CGC should increase, BUT val_2 balance should NOT be included in CGC
        assert_eq!(
            cgc_changed
                .expect("CGC should change")
                .new_custody_group_count,
            val_custody_units_1 + val_custody_units_3
        );
    }

    /// Update validator every epoch and assert cgc against expected values.
    fn register_validators_and_assert_cgc(
        custody_context: &CustodyContext,
        validators_and_expected_cgc_changed: Vec<(ValidatorsAndBalances, Option<u64>)>,
        spec: &ChainSpec,
    ) {
        for (idx, (validators_and_balance, expected_cgc_change)) in
            validators_and_expected_cgc_changed.into_iter().enumerate()
        {
            let epoch = Epoch::new(idx as u64);
            let updated_custody_count_opt = custody_context
                .register_validators::<E>(
                    validators_and_balance,
                    epoch.start_slot(E::slots_per_epoch()),
                    spec,
                )
                .map(|c| c.new_custody_group_count);

            assert_eq!(updated_custody_count_opt, expected_cgc_change);
        }
    }
}

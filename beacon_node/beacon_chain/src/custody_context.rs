use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicU64, Ordering},
};
use tracing::{debug, warn};
use types::{ChainSpec, ColumnIndex, Epoch, EthSpec, Slot};

/// A delay before making the CGC change effective to the data availability checker.
pub const CUSTODY_CHANGE_DA_EFFECTIVE_DELAY_SECONDS: u64 = 30;

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
    /// This map is only pruned during custody backfill. If epoch 11 has custody requirements
    /// that are then backfilled to epoch 10, the value at epoch 11 will be removed and epoch 10
    /// will be added to the map instead. This should keep map size constrained to a maximum
    /// value of 128.
    ///
    /// If the node's is started with a cgc override (i.e. supernode/semi-supernode flag), the cgc
    /// value is inserted into this map on initialisation with epoch set to 0. For a semi-supernode,
    /// this means the custody requirement can still be increased if validator custody exceeds
    /// 64 columns.
    epoch_validator_custody_requirements: BTreeMap<Epoch, u64>,
}

impl ValidatorRegistrations {
    /// Initialise the validator registration with some default custody requirements.
    ///
    /// If a `cgc_override` value is specified, the cgc value is inserted into the registration map
    /// and is equivalent to registering validator(s) with the same custody requirement.
    ///
    /// The node will backfill all the way back to either data_availability_boundary or fulu epoch,
    /// and because this is a fresh node, setting the epoch to 0 is fine, as backfill will be done via
    /// backfill sync instead of column backfill.
    fn new(cgc_override: Option<u64>) -> Self {
        let mut registrations = ValidatorRegistrations {
            validators: Default::default(),
            epoch_validator_custody_requirements: Default::default(),
        };
        if let Some(custody_count) = cgc_override {
            registrations
                .epoch_validator_custody_requirements
                .insert(Epoch::new(0), custody_count);
        }
        registrations
    }

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

        debug!(
            validator_custody_units,
            validator_custody_requirement, "Registered validators"
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
                .insert(effective_epoch, validator_custody_requirement);
            Some((effective_epoch, validator_custody_requirement))
        } else {
            None
        }
    }

    /// Updates the `epoch -> cgc` map after custody backfill has been completed for
    /// the specified epoch.
    ///
    /// This is done by pruning all values on/after `effective_epoch` and updating the map to store
    /// the latest validator custody requirements for the `effective_epoch`.
    pub fn backfill_validator_custody_requirements(
        &mut self,
        effective_epoch: Epoch,
        expected_cgc: u64,
    ) {
        if let Some(latest_validator_custody) = self.latest_validator_custody_requirement() {
            // If the expected cgc isn't equal to the latest validator custody a very recent cgc change may have occurred.
            // We should not update the mapping.
            if expected_cgc != latest_validator_custody {
                return;
            }
            // Delete records if
            // 1. The epoch is greater than or equal than `effective_epoch`
            // 2. the cgc requirements match the latest validator custody requirements
            self.epoch_validator_custody_requirements
                .retain(|&epoch, custody_requirement| {
                    !(epoch >= effective_epoch && *custody_requirement == latest_validator_custody)
                });

            self.epoch_validator_custody_requirements
                .insert(effective_epoch, latest_validator_custody);
        }
    }

    /// Updates the `epoch -> cgc` map by pruning records before `effective_epoch`
    /// while setting the `cgc` at `effective_epoch` to the latest validator custody requirement.
    ///
    /// This is used to restart custody backfill sync at `effective_epoch`
    pub fn reset_validator_custody_requirements(&mut self, effective_epoch: Epoch) {
        if let Some(latest_validator_custody_requirements) =
            self.latest_validator_custody_requirement()
        {
            self.epoch_validator_custody_requirements
                .retain(|&epoch, _| epoch >= effective_epoch);

            self.epoch_validator_custody_requirements
                .insert(effective_epoch, latest_validator_custody_requirements);
        };
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

/// Indicates the different "modes" that a node can run based on the cli
/// parameters that are relevant for computing the custody count.
///
/// The custody count is derived from 2 values:
/// 1. The number of validators attached to the node and the spec parameters
///    that attach custody weight to attached validators.
/// 2. The cli parameters that the current node is running with.
///
/// We always persist the validator custody units to the db across restarts
/// such that we know the validator custody units at any given epoch in the past.
/// However, knowing the cli parameter at any given epoch is a pain to maintain
/// and unnecessary.
///
/// Therefore, the custody count at any point in time is calculated as the max of
/// the validator custody at that time and the current cli params.
///
/// Choosing the max ensures that we always have the minimum required columns, and
/// we can adjust the `status.earliest_available_slot` value to indicate to our peers
/// the columns that we can guarantee to serve.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum NodeCustodyType {
    /// The node is running with cli parameters to indicate that it
    /// wants to subscribe to all columns.
    Supernode,
    /// The node is running with cli parameters to indicate that it
    /// wants to subscribe to the minimum number of columns to enable
    /// reconstruction (50%) of the full blob data on demand.
    SemiSupernode,
    /// The node isn't running with any explicit cli parameters
    /// or is running with cli parameters to indicate that it wants
    /// to only subscribe to the minimal custody requirements.
    #[default]
    Fullnode,
}

impl NodeCustodyType {
    pub fn get_custody_count_override(&self, spec: &ChainSpec) -> Option<u64> {
        match self {
            Self::Fullnode => None,
            Self::SemiSupernode => Some(spec.number_of_custody_groups / 2),
            Self::Supernode => Some(spec.number_of_custody_groups),
        }
    }
}

/// Contains all the information the node requires to calculate the
/// number of columns to be custodied when checking for DA.
#[derive(Debug)]
pub struct CustodyContext<E: EthSpec> {
    /// The Number of custody groups required based on the number of validators
    /// that is attached to this node.
    ///
    /// This is the number that we use to compute the custody group count that
    /// we require for data availability check, and we use to advertise to our peers in the metadata
    /// and enr values.
    validator_custody_count: AtomicU64,
    /// Maintains all the validators that this node is connected to currently
    validator_registrations: RwLock<ValidatorRegistrations>,
    /// Stores an immutable, ordered list of all data column indices as determined by the node's NodeID
    /// on startup. This used to determine the node's custody columns.
    ordered_custody_column_indices: Vec<ColumnIndex>,
    _phantom_data: PhantomData<E>,
}

impl<E: EthSpec> CustodyContext<E> {
    /// Create a new custody default custody context object when no persisted object
    /// exists.
    ///
    /// The `node_custody_type` value is based on current cli parameters.
    pub fn new(
        node_custody_type: NodeCustodyType,
        ordered_custody_column_indices: Vec<ColumnIndex>,
        spec: &ChainSpec,
    ) -> Self {
        let cgc_override = node_custody_type.get_custody_count_override(spec);
        // If there's no override, we initialise `validator_custody_count` to 0. This has been the
        // existing behaviour and we maintain this for now to avoid a semantic schema change until
        // a later release.
        Self {
            validator_custody_count: AtomicU64::new(cgc_override.unwrap_or(0)),
            validator_registrations: RwLock::new(ValidatorRegistrations::new(cgc_override)),
            ordered_custody_column_indices,
            _phantom_data: PhantomData,
        }
    }

    /// Restore the custody context from disk.
    ///
    /// # Behavior
    /// * If [`NodeCustodyType::get_custody_count_override`] < validator_custody_at_head, it means
    ///   validators have increased the CGC beyond the derived CGC from cli flags. We ignore the CLI input.
    /// * If [`NodeCustodyType::get_custody_count_override`] > validator_custody_at_head, it means the user has
    ///   changed the node's custody type via either the --supernode or --semi-supernode flags which
    ///   has resulted in a CGC increase. **The new CGC will be made effective from the next epoch**.
    ///
    /// # Returns
    /// A tuple containing:
    /// * `Self` - The restored custody context with updated CGC at head
    /// * `Option<CustodyCountChanged>` - `Some` if the CLI flag caused a CGC increase (triggering backfill),
    ///   `None` if no CGC change occurred or reduction was prevented
    pub fn new_from_persisted_custody_context(
        ssz_context: CustodyContextSsz,
        node_custody_type: NodeCustodyType,
        head_epoch: Epoch,
        ordered_custody_column_indices: Vec<ColumnIndex>,
        spec: &ChainSpec,
    ) -> (Self, Option<CustodyCountChanged>) {
        let CustodyContextSsz {
            mut validator_custody_at_head,
            mut epoch_validator_custody_requirements,
            persisted_is_supernode: _,
        } = ssz_context;

        let mut custody_count_changed = None;

        if let Some(cgc_from_cli) = node_custody_type.get_custody_count_override(spec) {
            debug!(
                ?node_custody_type,
                persisted_custody_count = validator_custody_at_head,
                "Initialising from persisted custody context"
            );

            if cgc_from_cli > validator_custody_at_head {
                // Make the CGC from CLI effective from the next epoch
                let effective_epoch = head_epoch + 1;
                let old_custody_group_count = validator_custody_at_head;
                validator_custody_at_head = cgc_from_cli;

                let sampling_count = spec
                    .sampling_size_custody_groups(cgc_from_cli)
                    .expect("should compute node sampling size from valid chain spec");

                epoch_validator_custody_requirements.push((effective_epoch, cgc_from_cli));

                custody_count_changed = Some(CustodyCountChanged {
                    new_custody_group_count: validator_custody_at_head,
                    old_custody_group_count,
                    sampling_count,
                    effective_epoch,
                });

                debug!(
                    info = "new CGC will be effective from the next epoch",
                    ?node_custody_type,
                    old_cgc = old_custody_group_count,
                    new_cgc = validator_custody_at_head,
                    effective_epoch = %effective_epoch,
                    "Node custody type change caused a custody count increase",
                );
            } else if cgc_from_cli < validator_custody_at_head {
                // We don't currently support reducing CGC for simplicity.
                // A common scenario is that user may restart with a CLI flag, but the validators
                // are only attached later, and we end up having CGC inconsistency.
                warn!(
                    info = "node will continue to run with the current custody count",
                    current_custody_count = validator_custody_at_head,
                    node_custody_type = ?node_custody_type,
                    "Reducing CGC is currently not supported without a resync and will have no effect",
                );
            }
        }

        let custody_context = CustodyContext {
            validator_custody_count: AtomicU64::new(validator_custody_at_head),
            validator_registrations: RwLock::new(ValidatorRegistrations {
                validators: Default::default(),
                epoch_validator_custody_requirements: epoch_validator_custody_requirements
                    .into_iter()
                    .collect(),
            }),
            ordered_custody_column_indices,
            _phantom_data: PhantomData,
        };

        (custody_context, custody_count_changed)
    }

    /// Register a new validator index and updates the list of validators if required.
    ///
    /// Also modifies the internal structures if the validator custody has changed to
    /// update the `custody_column_count`.
    ///
    /// Returns `Some` along with the updated custody group count if it has changed, otherwise returns `None`.
    pub fn register_validators(
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

        let current_cgc = self.validator_custody_count.load(Ordering::Relaxed);

        if new_validator_custody != current_cgc {
            debug!(
                old_count = current_cgc,
                new_count = new_validator_custody,
                "Validator count at head updated"
            );
            self.validator_custody_count
                .store(new_validator_custody, Ordering::Relaxed);

            let updated_cgc = self.custody_group_count_at_head(spec);
            // Send the message to network only if there are more columns subnets to subscribe to
            if updated_cgc > current_cgc {
                debug!(
                    old_cgc = current_cgc,
                    updated_cgc, "Custody group count updated"
                );
                return Some(CustodyCountChanged {
                    new_custody_group_count: updated_cgc,
                    old_custody_group_count: current_cgc,
                    sampling_count: self.num_of_custody_groups_to_sample(effective_epoch, spec),
                    effective_epoch,
                });
            }
        }

        None
    }

    /// This function is used to determine the custody group count at head ONLY.
    /// Do NOT use this directly for data availability check, use `self.sampling_size` instead as
    /// CGC can change over epochs.
    pub fn custody_group_count_at_head(&self, spec: &ChainSpec) -> u64 {
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
    pub fn custody_group_count_at_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> u64 {
        self.validator_registrations
            .read()
            .custody_requirement_at_epoch(epoch)
            .unwrap_or(spec.custody_requirement)
    }

    /// Returns the count of custody groups this node must _sample_ for a block at `epoch` to import.
    pub fn num_of_custody_groups_to_sample(&self, epoch: Epoch, spec: &ChainSpec) -> u64 {
        let custody_group_count = self.custody_group_count_at_epoch(epoch, spec);
        spec.sampling_size_custody_groups(custody_group_count)
            .expect("should compute node sampling size from valid chain spec")
    }

    /// Returns the count of columns this node must _sample_ for a block at `epoch` to import.
    pub fn num_of_data_columns_to_sample(&self, epoch: Epoch, spec: &ChainSpec) -> usize {
        let custody_group_count = self.custody_group_count_at_epoch(epoch, spec);
        spec.sampling_size_columns::<E>(custody_group_count)
            .expect("should compute node sampling size from valid chain spec")
    }

    /// Returns whether the node should attempt reconstruction at a given epoch.
    pub fn should_attempt_reconstruction(&self, epoch: Epoch, spec: &ChainSpec) -> bool {
        let min_columns_for_reconstruction = E::number_of_columns() / 2;
        // performing reconstruction is not necessary if sampling column count is exactly 50%,
        // because the node doesn't need the remaining columns.
        self.num_of_data_columns_to_sample(epoch, spec) > min_columns_for_reconstruction
    }

    /// Returns the ordered list of column indices that should be sampled for data availability checking at the given epoch.
    ///
    /// # Parameters
    /// * `epoch` - Epoch to determine sampling columns for
    /// * `spec` - Chain specification containing sampling parameters
    ///
    /// # Returns
    /// A slice of ordered column indices that should be sampled for this epoch based on the node's custody configuration
    pub fn sampling_columns_for_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> &[ColumnIndex] {
        let num_of_columns_to_sample = self.num_of_data_columns_to_sample(epoch, spec);
        &self.ordered_custody_column_indices[..num_of_columns_to_sample]
    }

    /// Returns the ordered list of column indices that the node is assigned to custody
    /// (and advertised to peers) at the given epoch. If epoch is `None`, this function
    /// computes the custody columns at head.
    ///
    /// This method differs from [`self::sampling_columns_for_epoch`] which returns all sampling columns.
    /// The columns returned by this method are either identical to or a subset of the sampling columns,
    /// representing only those columns that this node is responsible for maintaining custody of.
    ///
    /// # Parameters
    /// * `epoch_opt` - Optional epoch to determine custody columns for.
    ///
    /// # Returns
    /// A slice of ordered custody column indices for this epoch based on the node's custody configuration
    pub fn custody_columns_for_epoch(
        &self,
        epoch_opt: Option<Epoch>,
        spec: &ChainSpec,
    ) -> &[ColumnIndex] {
        let custody_group_count = if let Some(epoch) = epoch_opt {
            self.custody_group_count_at_epoch(epoch, spec) as usize
        } else {
            self.custody_group_count_at_head(spec) as usize
        };

        // This is an unnecessary conversion for spec compliance, basically just multiplying by 1.
        let columns_per_custody_group = spec.data_columns_per_group::<E>() as usize;
        let custody_column_count = columns_per_custody_group * custody_group_count;

        &self.ordered_custody_column_indices[..custody_column_count]
    }

    /// The node has completed backfill for this epoch. Update the internal records so the function
    /// [`Self::custody_columns_for_epoch()`] returns up-to-date results.
    pub fn update_and_backfill_custody_count_at_epoch(
        &self,
        effective_epoch: Epoch,
        expected_cgc: u64,
    ) {
        self.validator_registrations
            .write()
            .backfill_validator_custody_requirements(effective_epoch, expected_cgc);
    }

    /// The node is attempting to restart custody backfill. Update the internal records so that
    /// custody backfill can start backfilling at `effective_epoch`.
    pub fn reset_validator_custody_requirements(&self, effective_epoch: Epoch) {
        self.validator_registrations
            .write()
            .reset_validator_custody_requirements(effective_epoch);
    }
}

/// Indicates that the custody group count (CGC) has increased.
///
/// CGC increases can occur due to:
/// 1. Validator registrations increasing effective balance beyond current CGC
/// 2. CLI flag changes (e.g., switching to --supernode or --semi-supernode)
///
/// This struct is used to trigger column backfill and network subnet subscription updates.
pub struct CustodyCountChanged {
    pub new_custody_group_count: u64,
    pub old_custody_group_count: u64,
    pub sampling_count: u64,
    pub effective_epoch: Epoch,
}

/// The custody information that gets persisted across runs.
#[derive(Debug, Encode, Decode, Clone)]
pub struct CustodyContextSsz {
    pub validator_custody_at_head: u64,
    /// DEPRECATED. This field is no longer in used and will be removed in a future release.
    pub persisted_is_supernode: bool,
    pub epoch_validator_custody_requirements: Vec<(Epoch, u64)>,
}

impl<E: EthSpec> From<&CustodyContext<E>> for CustodyContextSsz {
    fn from(context: &CustodyContext<E>) -> Self {
        CustodyContextSsz {
            validator_custody_at_head: context.validator_custody_count.load(Ordering::Relaxed),
            // This field is deprecated and has no effect
            persisted_is_supernode: false,
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
    use super::*;
    use crate::test_utils::generate_data_column_indices_rand_order;
    use types::MainnetEthSpec;

    type E = MainnetEthSpec;

    fn setup_custody_context(
        spec: &ChainSpec,
        head_epoch: Epoch,
        epoch_and_cgc_tuples: Vec<(Epoch, u64)>,
    ) -> CustodyContext<E> {
        let cgc_at_head = epoch_and_cgc_tuples.last().unwrap().1;
        let ssz_context = CustodyContextSsz {
            validator_custody_at_head: cgc_at_head,
            persisted_is_supernode: false,
            epoch_validator_custody_requirements: epoch_and_cgc_tuples,
        };

        let (custody_context, _) = CustodyContext::<E>::new_from_persisted_custody_context(
            ssz_context,
            NodeCustodyType::Fullnode,
            head_epoch,
            generate_data_column_indices_rand_order::<E>(),
            spec,
        );

        custody_context
    }

    fn complete_backfill_for_epochs(
        custody_context: &CustodyContext<E>,
        start_epoch: Epoch,
        end_epoch: Epoch,
        expected_cgc: u64,
    ) {
        assert!(start_epoch >= end_epoch);
        // Call from end_epoch down to start_epoch (inclusive), simulating backfill
        for epoch in (end_epoch.as_u64()..=start_epoch.as_u64()).rev() {
            custody_context
                .update_and_backfill_custody_count_at_epoch(Epoch::new(epoch), expected_cgc);
        }
    }

    /// Helper function to test CGC increases when switching node custody types.
    /// Verifies that CustodyCountChanged is returned with correct values and
    /// that custody_group_count_at_epoch returns appropriate values for current and next epoch.
    fn assert_custody_type_switch_increases_cgc(
        persisted_cgc: u64,
        target_node_custody_type: NodeCustodyType,
        expected_new_cgc: u64,
        head_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        let ssz_context = CustodyContextSsz {
            validator_custody_at_head: persisted_cgc,
            persisted_is_supernode: false,
            epoch_validator_custody_requirements: vec![(Epoch::new(0), persisted_cgc)],
        };

        let (custody_context, custody_count_changed) =
            CustodyContext::<E>::new_from_persisted_custody_context(
                ssz_context,
                target_node_custody_type,
                head_epoch,
                generate_data_column_indices_rand_order::<E>(),
                spec,
            );

        // Verify CGC increased
        assert_eq!(
            custody_context.custody_group_count_at_head(spec),
            expected_new_cgc,
            "cgc should increase from {} to {}",
            persisted_cgc,
            expected_new_cgc
        );

        // Verify CustodyCountChanged is returned with correct values
        let cgc_changed = custody_count_changed.expect("CustodyCountChanged should be returned");
        assert_eq!(
            cgc_changed.new_custody_group_count, expected_new_cgc,
            "new_custody_group_count should be {}",
            expected_new_cgc
        );
        assert_eq!(
            cgc_changed.old_custody_group_count, persisted_cgc,
            "old_custody_group_count should be {}",
            persisted_cgc
        );
        assert_eq!(
            cgc_changed.effective_epoch,
            head_epoch + 1,
            "effective epoch should be head_epoch + 1"
        );
        assert_eq!(
            cgc_changed.sampling_count,
            spec.sampling_size_custody_groups(expected_new_cgc)
                .expect("should compute sampling size"),
            "sampling_count should match expected value"
        );

        // Verify custody_group_count_at_epoch returns correct values
        assert_eq!(
            custody_context.custody_group_count_at_epoch(head_epoch, spec),
            persisted_cgc,
            "current epoch should still use old cgc ({})",
            persisted_cgc
        );
        assert_eq!(
            custody_context.custody_group_count_at_epoch(head_epoch + 1, spec),
            expected_new_cgc,
            "next epoch should use new cgc ({})",
            expected_new_cgc
        );
    }

    /// Helper function to test CGC reduction prevention when switching node custody types.
    /// Verifies that CGC stays at the persisted value and CustodyCountChanged is not returned.
    fn assert_custody_type_switch_unchanged_cgc(
        persisted_cgc: u64,
        target_node_custody_type: NodeCustodyType,
        head_epoch: Epoch,
        spec: &ChainSpec,
    ) {
        let ssz_context = CustodyContextSsz {
            validator_custody_at_head: persisted_cgc,
            persisted_is_supernode: false,
            epoch_validator_custody_requirements: vec![(Epoch::new(0), persisted_cgc)],
        };

        let (custody_context, custody_count_changed) =
            CustodyContext::<E>::new_from_persisted_custody_context(
                ssz_context,
                target_node_custody_type,
                head_epoch,
                generate_data_column_indices_rand_order::<E>(),
                spec,
            );

        // Verify CGC stays at persisted value (no reduction)
        assert_eq!(
            custody_context.custody_group_count_at_head(spec),
            persisted_cgc,
            "cgc should remain at {} (reduction not supported)",
            persisted_cgc
        );

        // Verify no CustodyCountChanged is returned (no change occurred)
        assert!(
            custody_count_changed.is_none(),
            "CustodyCountChanged should not be returned when CGC doesn't change"
        );
    }

    #[test]
    fn no_validators_supernode_default() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Supernode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            spec.number_of_custody_groups
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Epoch::new(0), &spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn no_validators_semi_supernode_default() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::SemiSupernode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            spec.number_of_custody_groups / 2
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Epoch::new(0), &spec),
            spec.number_of_custody_groups / 2
        );
    }

    #[test]
    fn no_validators_fullnode_default() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            spec.custody_requirement,
            "head custody count should be minimum spec custody requirement"
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Epoch::new(0), &spec),
            spec.samples_per_slot
        );
    }

    #[test]
    fn register_single_validator_should_update_cgc() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
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

        register_validators_and_assert_cgc::<E>(
            &custody_context,
            validators_and_expected_cgc_change,
            &spec,
        );
    }

    #[test]
    fn register_multiple_validators_should_update_cgc() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
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

        register_validators_and_assert_cgc::<E>(
            &custody_context,
            validators_and_expected_cgc,
            &spec,
        );
    }

    #[test]
    fn register_validators_should_not_update_cgc_for_supernode() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Supernode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
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

        register_validators_and_assert_cgc::<E>(
            &custody_context,
            validators_and_expected_cgc,
            &spec,
        );
        let current_epoch = Epoch::new(2);
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(current_epoch, &spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn cgc_change_should_be_effective_to_sampling_after_delay() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        let current_slot = Slot::new(10);
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let default_sampling_size =
            custody_context.num_of_custody_groups_to_sample(current_epoch, &spec);
        let validator_custody_units = 10;

        let _cgc_changed = custody_context.register_validators(
            vec![(
                0,
                validator_custody_units * spec.balance_per_additional_custody_group,
            )],
            current_slot,
            &spec,
        );

        // CGC update is not applied for `current_epoch`.
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(current_epoch, &spec),
            default_sampling_size
        );
        // CGC update is applied for the next epoch.
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(current_epoch + 1, &spec),
            validator_custody_units
        );
    }

    #[test]
    fn validator_dropped_after_no_registrations_within_expiry_should_not_reduce_cgc() {
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        let current_slot = Slot::new(10);
        let val_custody_units_1 = 10;
        let val_custody_units_2 = 5;

        // GIVEN val_1 and val_2 registered at `current_slot`
        let _ = custody_context.register_validators(
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
        let cgc_changed_opt = custody_context.register_validators(
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
        let spec = E::default_spec();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );
        let current_slot = Slot::new(10);
        let val_custody_units_1 = 10;
        let val_custody_units_2 = 5;
        let val_custody_units_3 = 6;

        // GIVEN val_1 and val_2 registered at `current_slot`
        let _ = custody_context.register_validators(
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
        let cgc_changed = custody_context.register_validators(
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

    /// Update the validator every epoch and assert cgc against expected values.
    fn register_validators_and_assert_cgc<E: EthSpec>(
        custody_context: &CustodyContext<E>,
        validators_and_expected_cgc_changed: Vec<(ValidatorsAndBalances, Option<u64>)>,
        spec: &ChainSpec,
    ) {
        for (idx, (validators_and_balance, expected_cgc_change)) in
            validators_and_expected_cgc_changed.into_iter().enumerate()
        {
            let epoch = Epoch::new(idx as u64);
            let updated_custody_count_opt = custody_context
                .register_validators(
                    validators_and_balance,
                    epoch.start_slot(E::slots_per_epoch()),
                    spec,
                )
                .map(|c| c.new_custody_group_count);

            assert_eq!(updated_custody_count_opt, expected_cgc_change);
        }
    }

    #[test]
    fn custody_columns_for_epoch_no_validators_fullnode() {
        let spec = E::default_spec();
        let ordered_custody_column_indices = generate_data_column_indices_rand_order::<E>();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            ordered_custody_column_indices,
            &spec,
        );

        assert_eq!(
            custody_context.custody_columns_for_epoch(None, &spec).len(),
            spec.custody_requirement as usize
        );
    }

    #[test]
    fn custody_columns_for_epoch_no_validators_supernode() {
        let spec = E::default_spec();
        let ordered_custody_column_indices = generate_data_column_indices_rand_order::<E>();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Supernode,
            ordered_custody_column_indices,
            &spec,
        );

        assert_eq!(
            custody_context.custody_columns_for_epoch(None, &spec).len(),
            spec.number_of_custody_groups as usize
        );
    }

    #[test]
    fn custody_columns_for_epoch_with_validators_should_match_cgc() {
        let spec = E::default_spec();
        let ordered_custody_column_indices = generate_data_column_indices_rand_order::<E>();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            ordered_custody_column_indices,
            &spec,
        );
        let val_custody_units = 10;

        let _ = custody_context.register_validators(
            vec![(
                0,
                val_custody_units * spec.balance_per_additional_custody_group,
            )],
            Slot::new(10),
            &spec,
        );

        assert_eq!(
            custody_context.custody_columns_for_epoch(None, &spec).len(),
            val_custody_units as usize
        );
    }

    #[test]
    fn custody_columns_for_epoch_specific_epoch_uses_epoch_cgc() {
        let spec = E::default_spec();
        let ordered_custody_column_indices = generate_data_column_indices_rand_order::<E>();
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::Fullnode,
            ordered_custody_column_indices,
            &spec,
        );
        let test_epoch = Epoch::new(5);

        let expected_cgc = custody_context.custody_group_count_at_epoch(test_epoch, &spec);
        assert_eq!(
            custody_context
                .custody_columns_for_epoch(Some(test_epoch), &spec)
                .len(),
            expected_cgc as usize
        );
    }

    #[test]
    fn restore_from_persisted_fullnode_no_validators() {
        let spec = E::default_spec();
        let ssz_context = CustodyContextSsz {
            validator_custody_at_head: 0, // no validators
            persisted_is_supernode: false,
            epoch_validator_custody_requirements: vec![],
        };

        let (custody_context, _) = CustodyContext::<E>::new_from_persisted_custody_context(
            ssz_context,
            NodeCustodyType::Fullnode,
            Epoch::new(0),
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );

        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            spec.custody_requirement,
            "restored custody group count should match fullnode default"
        );
    }

    /// Tests CLI flag change: Fullnode (CGC=0) → Supernode (CGC=128)
    /// CGC should increase and trigger backfill via CustodyCountChanged.
    #[test]
    fn restore_fullnode_then_switch_to_supernode_increases_cgc() {
        let spec = E::default_spec();
        let head_epoch = Epoch::new(10);
        let supernode_cgc = spec.number_of_custody_groups;

        assert_custody_type_switch_increases_cgc(
            0,
            NodeCustodyType::Supernode,
            supernode_cgc,
            head_epoch,
            &spec,
        );
    }

    /// Tests validator-driven CGC increase: Semi-supernode (CGC=64) → CGC=70
    /// Semi-supernode can exceed 64 when validator effective balance increases CGC.
    #[test]
    fn restore_semi_supernode_with_validators_can_exceed_64() {
        let spec = E::default_spec();
        let semi_supernode_cgc = spec.number_of_custody_groups / 2; // 64
        let custody_context = CustodyContext::<E>::new(
            NodeCustodyType::SemiSupernode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );

        // Verify initial CGC is 64 (semi-supernode)
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            semi_supernode_cgc,
            "initial cgc should be 64"
        );

        // Register validators with 70 custody units (exceeding semi-supernode default)
        let validator_custody_units = 70;
        let current_slot = Slot::new(10);
        let cgc_changed = custody_context.register_validators(
            vec![(
                0,
                validator_custody_units * spec.balance_per_additional_custody_group,
            )],
            current_slot,
            &spec,
        );

        // Verify CGC increased from 64 to 70
        assert!(
            cgc_changed.is_some(),
            "CustodyCountChanged should be returned"
        );
        let cgc_changed = cgc_changed.unwrap();
        assert_eq!(
            cgc_changed.new_custody_group_count, validator_custody_units,
            "cgc should increase to 70"
        );
        assert_eq!(
            cgc_changed.old_custody_group_count, semi_supernode_cgc,
            "old cgc should be 64"
        );

        // Verify the custody context reflects the new CGC
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            validator_custody_units,
            "custody_group_count_at_head should be 70"
        );
    }

    /// Tests CLI flag change prevention: Supernode (CGC=128) → Fullnode (CGC stays 128)
    /// CGC reduction is not supported - persisted value is retained.
    #[test]
    fn restore_supernode_then_switch_to_fullnode_uses_persisted() {
        let spec = E::default_spec();
        let supernode_cgc = spec.number_of_custody_groups;

        assert_custody_type_switch_unchanged_cgc(
            supernode_cgc,
            NodeCustodyType::Fullnode,
            Epoch::new(0),
            &spec,
        );
    }

    /// Tests CLI flag change prevention: Supernode (CGC=128) → Semi-supernode (CGC stays 128)
    /// CGC reduction is not supported - persisted value is retained.
    #[test]
    fn restore_supernode_then_switch_to_semi_supernode_keeps_supernode_cgc() {
        let spec = E::default_spec();
        let supernode_cgc = spec.number_of_custody_groups;
        let head_epoch = Epoch::new(10);

        assert_custody_type_switch_unchanged_cgc(
            supernode_cgc,
            NodeCustodyType::SemiSupernode,
            head_epoch,
            &spec,
        );
    }

    /// Tests CLI flag change: Fullnode with validators (CGC=32) → Semi-supernode (CGC=64)
    /// CGC should increase and trigger backfill via CustodyCountChanged.
    #[test]
    fn restore_fullnode_with_validators_then_switch_to_semi_supernode() {
        let spec = E::default_spec();
        let persisted_cgc = 32u64;
        let semi_supernode_cgc = spec.number_of_custody_groups / 2;
        let head_epoch = Epoch::new(10);

        assert_custody_type_switch_increases_cgc(
            persisted_cgc,
            NodeCustodyType::SemiSupernode,
            semi_supernode_cgc,
            head_epoch,
            &spec,
        );
    }

    /// Tests CLI flag change: Semi-supernode (CGC=64) → Supernode (CGC=128)
    /// CGC should increase and trigger backfill via CustodyCountChanged.
    #[test]
    fn restore_semi_supernode_then_switch_to_supernode() {
        let spec = E::default_spec();
        let semi_supernode_cgc = spec.number_of_custody_groups / 2;
        let supernode_cgc = spec.number_of_custody_groups;
        let head_epoch = Epoch::new(10);

        assert_custody_type_switch_increases_cgc(
            semi_supernode_cgc,
            NodeCustodyType::Supernode,
            supernode_cgc,
            head_epoch,
            &spec,
        );
    }

    /// Tests CLI flag change: Fullnode with validators (CGC=32) → Supernode (CGC=128)
    /// CGC should increase and trigger backfill via CustodyCountChanged.
    #[test]
    fn restore_with_cli_flag_increases_cgc_from_nonzero() {
        let spec = E::default_spec();
        let persisted_cgc = 32u64;
        let supernode_cgc = spec.number_of_custody_groups;
        let head_epoch = Epoch::new(10);

        assert_custody_type_switch_increases_cgc(
            persisted_cgc,
            NodeCustodyType::Supernode,
            supernode_cgc,
            head_epoch,
            &spec,
        );
    }

    #[test]
    fn restore_with_validator_custody_history_across_epochs() {
        let spec = E::default_spec();
        let initial_cgc = 8u64;
        let increased_cgc = 16u64;
        let final_cgc = 32u64;

        let ssz_context = CustodyContextSsz {
            validator_custody_at_head: final_cgc,
            persisted_is_supernode: false,
            epoch_validator_custody_requirements: vec![
                (Epoch::new(0), initial_cgc),
                (Epoch::new(10), increased_cgc),
                (Epoch::new(20), final_cgc),
            ],
        };

        let (custody_context, _) = CustodyContext::<E>::new_from_persisted_custody_context(
            ssz_context,
            NodeCustodyType::Fullnode,
            Epoch::new(20),
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        );

        // Verify head uses latest value
        assert_eq!(
            custody_context.custody_group_count_at_head(&spec),
            final_cgc
        );

        // Verify historical epoch lookups work correctly
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(5), &spec),
            initial_cgc,
            "epoch 5 should use initial cgc"
        );
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(15), &spec),
            increased_cgc,
            "epoch 15 should use increased cgc"
        );
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(25), &spec),
            final_cgc,
            "epoch 25 should use final cgc"
        );

        // Verify sampling size calculation uses correct historical values
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Epoch::new(5), &spec),
            spec.samples_per_slot,
            "sampling at epoch 5 should use spec minimum since cgc is at minimum"
        );
        assert_eq!(
            custody_context.num_of_custody_groups_to_sample(Epoch::new(25), &spec),
            final_cgc,
            "sampling at epoch 25 should match final cgc"
        );
    }

    #[test]
    fn backfill_single_cgc_increase_updates_past_epochs() {
        let spec = E::default_spec();
        let final_cgc = 32u64;
        let default_cgc = spec.custody_requirement;

        // Setup: Node restart after validators were registered, causing CGC increase to 32 at epoch 20
        let head_epoch = Epoch::new(20);
        let epoch_and_cgc_tuples = vec![(head_epoch, final_cgc)];
        let custody_context = setup_custody_context(&spec, head_epoch, epoch_and_cgc_tuples);
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(15), &spec),
            default_cgc,
        );

        // Backfill from epoch 20 down to 15 (simulating backfill)
        complete_backfill_for_epochs(&custody_context, head_epoch, Epoch::new(15), final_cgc);

        // After backfilling to epoch 15, it should use latest CGC (32)
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(15), &spec),
            final_cgc,
        );
        assert_eq!(
            custody_context
                .custody_columns_for_epoch(Some(Epoch::new(15)), &spec)
                .len(),
            final_cgc as usize,
        );

        // Prior epoch should still return the original CGC
        assert_eq!(
            custody_context.custody_group_count_at_epoch(Epoch::new(14), &spec),
            default_cgc,
        );
    }

    #[test]
    fn backfill_with_multiple_cgc_increases_prunes_map_correctly() {
        let spec = E::default_spec();
        let initial_cgc = 8u64;
        let mid_cgc = 16u64;
        let final_cgc = 32u64;

        // Setup: Node restart after multiple validator registrations causing CGC increases
        let head_epoch = Epoch::new(20);
        let epoch_and_cgc_tuples = vec![
            (Epoch::new(0), initial_cgc),
            (Epoch::new(10), mid_cgc),
            (head_epoch, final_cgc),
        ];
        let custody_context = setup_custody_context(&spec, head_epoch, epoch_and_cgc_tuples);

        // Backfill to epoch 15 (between the two CGC increases)
        complete_backfill_for_epochs(&custody_context, Epoch::new(20), Epoch::new(15), final_cgc);

        // Verify epochs 15 - 20 return latest CGC (32)
        for epoch in 15..=20 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                final_cgc,
            );
        }

        // Verify epochs 10-14 still return mid_cgc (16)
        for epoch in 10..14 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                mid_cgc,
            );
        }
    }

    #[test]
    fn attempt_backfill_with_invalid_cgc() {
        let spec = E::default_spec();
        let initial_cgc = 8u64;
        let mid_cgc = 16u64;
        let final_cgc = 32u64;

        // Setup: Node restart after multiple validator registrations causing CGC increases
        let head_epoch = Epoch::new(20);
        let epoch_and_cgc_tuples = vec![
            (Epoch::new(0), initial_cgc),
            (Epoch::new(10), mid_cgc),
            (head_epoch, final_cgc),
        ];
        let custody_context = setup_custody_context(&spec, head_epoch, epoch_and_cgc_tuples);

        // Backfill to epoch 15 (between the two CGC increases)
        complete_backfill_for_epochs(&custody_context, Epoch::new(20), Epoch::new(15), final_cgc);

        // Verify epochs 15 - 20 return latest CGC (32)
        for epoch in 15..=20 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                final_cgc,
            );
        }

        // Attempt backfill with an incorrect cgc value
        complete_backfill_for_epochs(
            &custody_context,
            Epoch::new(20),
            Epoch::new(15),
            initial_cgc,
        );

        // Verify epochs 15 - 20 still return latest CGC (32)
        for epoch in 15..=20 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                final_cgc,
            );
        }

        // Verify epochs 10-14 still return mid_cgc (16)
        for epoch in 10..14 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                mid_cgc,
            );
        }
    }

    #[test]
    fn reset_validator_custody_requirements() {
        let spec = E::default_spec();
        let minimum_cgc = 4u64;
        let initial_cgc = 8u64;
        let mid_cgc = 16u64;
        let final_cgc = 32u64;

        // Setup: Node restart after multiple validator registrations causing CGC increases
        let head_epoch = Epoch::new(20);
        let epoch_and_cgc_tuples = vec![
            (Epoch::new(0), initial_cgc),
            (Epoch::new(10), mid_cgc),
            (head_epoch, final_cgc),
        ];
        let custody_context = setup_custody_context(&spec, head_epoch, epoch_and_cgc_tuples);

        // Backfill from epoch 20 to 9
        complete_backfill_for_epochs(&custody_context, Epoch::new(20), Epoch::new(9), final_cgc);

        // Reset validator custody requirements to the latest cgc requirements at `head_epoch` up to the boundary epoch
        custody_context.reset_validator_custody_requirements(head_epoch);

        // Verify epochs 0 - 19 return the minimum cgc requirement because of the validator custody requirement reset
        for epoch in 0..=19 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                minimum_cgc,
            );
        }

        // Verify epoch 20 returns a CGC of 32
        assert_eq!(
            custody_context.custody_group_count_at_epoch(head_epoch, &spec),
            final_cgc
        );

        // Rerun Backfill to epoch 20
        complete_backfill_for_epochs(&custody_context, Epoch::new(20), Epoch::new(0), final_cgc);

        // Verify epochs 0 - 20 return the final cgc requirements
        for epoch in 0..=20 {
            assert_eq!(
                custody_context.custody_group_count_at_epoch(Epoch::new(epoch), &spec),
                final_cgc,
            );
        }
    }
}

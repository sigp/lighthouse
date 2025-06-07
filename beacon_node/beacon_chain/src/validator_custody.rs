use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::RwLock;

use ssz_derive::{Decode, Encode};
use tokio::sync::broadcast::{channel, Receiver, Sender};
use types::{ChainSpec, Epoch, EthSpec, Slot};

const CHANNEL_CAPACITY: usize = 10;

/// TODO(pawan): this currently just registers increases in validator count.
/// Does not handle decreasing validator counts
#[derive(Default, Debug)]
struct ValidatorRegistrations {
    /// Set of all validators that is registered to this node along with its effective balance
    /// in increments of `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP`
    ///
    /// Key is validator index and value is effective_balance // BALANCE_PER_ADDITIONAL_CUSTODY_GROUP.
    validators: HashMap<usize, u64>,
    /// Maintains the validator custody requirement at a given epoch.
    ///
    /// Note: Only stores the epoch value when there's a change in custody requirement.
    /// So if epoch 10 and 11 has the same custody requirement, only 10 is stored.
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
        // This is the "weight" of the validator based on the effective balance
        let num_validators_for_effective_balance =
            effective_balance / spec.balance_per_additional_custody_group;
        self.validators
            .insert(validator_index, num_validators_for_effective_balance);

        // Each `BALANCE_PER_ADDITIONAL_CUSTODY_GROUP` effectively contributes one unit of "weight".
        let validator_count_at_epoch = self.validators.values().sum();
        let validator_custody_requirement =
            get_validators_custody_requirement(validator_count_at_epoch, spec);

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
            validator_count = validator_count_at_epoch,
            validator_custody_requirement,
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
    /// This is the number that we use to compute the cgc value that
    /// we advertise to our peers in the metadata and enr values.
    advertised_validator_custody_count: AtomicU64,
    /// This is the validator custody count that we use to compute the number of columns we need to
    /// custody at head (while syncing or when receiving gossip).
    validator_custody_count_at_head: AtomicU64,
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
    sender: Sender<CustodyContextMessage>,
}

impl CustodyContext {
    /// Create a new custody default custody context object when no persisted object
    /// exists.
    ///
    /// The `is_supernode` value is based on current cli parameters.
    pub fn new(is_supernode: bool) -> Self {
        let (sender, _) = channel(CHANNEL_CAPACITY);

        Self {
            advertised_validator_custody_count: AtomicU64::new(0),
            validator_custody_count_at_head: AtomicU64::new(0),
            current_is_supernode: is_supernode,
            persisted_is_supernode: is_supernode,
            validator_registrations: Default::default(),
            sender,
        }
    }

    /// Deserialize a `CustodyContext` from SSZ bytes.
    pub fn new_from_persisted_custody_context(
        ssz_context: CustodyContextSsz,
        is_supernode: bool,
    ) -> Self {
        let (sender, _) = channel(CHANNEL_CAPACITY);
        CustodyContext {
            advertised_validator_custody_count: AtomicU64::new(
                ssz_context.advertised_validator_custody,
            ),
            validator_custody_count_at_head: AtomicU64::new(ssz_context.validator_custody_at_head),
            current_is_supernode: is_supernode,
            persisted_is_supernode: ssz_context.persisted_is_supernode,
            validator_registrations: Default::default(),
            sender,
        }
    }

    pub fn subscribe(&self) -> Receiver<CustodyContextMessage> {
        self.sender.subscribe()
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
        // Complete all registrations
        let mut registrations = self.validator_registrations.write();
        for (validator_index, effective_balance) in validators_and_balance {
            registrations.register_validator::<E>(validator_index, effective_balance, slot, spec);
        }

        // Completed registrations, now check if the validator custody requirement has changed
        let Some(new_validator_custody) = registrations.latest_validator_custody_requirement()
        else {
            return;
        };

        let current_cgc = self.custody_group_count(spec);
        let validator_custody_count_at_head =
            self.validator_custody_count_at_head.load(Ordering::Relaxed);

        if new_validator_custody != validator_custody_count_at_head {
            tracing::debug!(
                old_count = validator_custody_count_at_head,
                new_count = new_validator_custody,
                "Validator count at head updated"
            );
            self.validator_custody_count_at_head
                .store(new_validator_custody, Ordering::Relaxed);

            let updated_cgc = self.custody_group_count(spec);
            // Send the message to network only if there are more columns subnets to subscribe to
            if updated_cgc > current_cgc {
                tracing::debug!(
                    old_cgc = current_cgc,
                    updated_cgc,
                    "Custody group count updated"
                );
                if let Err(e) = self
                    .sender
                    .send(CustodyContextMessage::HeadCustodyCountChanged {
                        new_custody_count: updated_cgc,
                    })
                {
                    tracing::error!(error=?e, "Failed to send custody context message");
                }
            }
        }
    }

    /// The custody count that we advertise to our peers in our metadata and
    /// enr values.
    pub fn advertised_custody_group_count(&self, spec: &ChainSpec) -> u64 {
        if self.persisted_is_supernode {
            return spec.number_of_custody_groups;
        }
        let advertised_validator_custody = self
            .advertised_validator_custody_count
            .load(Ordering::Relaxed);

        // If there are no validators, return the minimum custody_requirement
        if advertised_validator_custody > 0 {
            advertised_validator_custody
        } else {
            spec.custody_requirement
        }
    }

    /// The custody count that we use to custody columns currently.
    ///
    /// This function should be called when figuring out how many columns we
    /// need to custody when receiving blocks over gossip/rpc or during sync.
    pub fn custody_group_count(&self, spec: &ChainSpec) -> u64 {
        if self.current_is_supernode {
            return spec.number_of_custody_groups;
        }
        let validator_custody_count_at_head =
            self.validator_custody_count_at_head.load(Ordering::Relaxed);

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

// write a service that emits events when internal values change
#[derive(Debug, Clone)]
pub enum CustodyContextMessage {
    /// The custody count changed because of a change in the
    /// number of validators being managed.
    ///
    /// This should trigger actions downstream like
    /// subscribing/unsubscribing new subnets/
    /// backfilling required columns.
    HeadCustodyCountChanged { new_custody_count: u64 },
    /// The advertised custody count has changed.
    ///
    /// This should trigger downstream actions like setting
    /// a new cgc value in the enr and metadata fields and
    /// performing any related cleanup actions.
    AdvertisedCustodyCountChanged { new_custody_count: u64 },
}

/// The custody information that gets persisted across runs.
#[derive(Debug, Encode, Decode, Clone)]
pub struct CustodyContextSsz {
    advertised_validator_custody: u64,
    validator_custody_at_head: u64,
    persisted_is_supernode: bool,
}

impl From<&CustodyContext> for CustodyContextSsz {
    fn from(context: &CustodyContext) -> Self {
        CustodyContextSsz {
            advertised_validator_custody: context
                .advertised_validator_custody_count
                .load(Ordering::Relaxed)
                .clone(),
            validator_custody_at_head: context
                .validator_custody_count_at_head
                .load(Ordering::Relaxed)
                .clone(),
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
            custody_context.custody_group_count(&spec),
            spec.number_of_custody_groups
        );
        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
            spec.number_of_custody_groups
        );
    }

    #[test]
    fn fullnode() {
        // fullnode without validators
        let custody_context = CustodyContext::new(false);
        let spec = E::default_spec();
        assert_eq!(
            custody_context.custody_group_count(&spec),
            spec.custody_requirement,
            "head custody count should be minimum spec custody requirement"
        );
        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
            spec.custody_requirement,
            "advertised custody count should be minimum spec custody requirement"
        );

        // add 1 validator
        custody_context.register_validator::<E>(vec![(0, 32_000_000_000)], Slot::new(0), &spec);

        assert_eq!(
            custody_context.custody_group_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement,
            "head custody count should increase with 1 validator"
        );

        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
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
            custody_context.custody_group_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement,
            "head custody count should should be same as with 1 validator"
        );

        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );

        // adding 1 more validator should increase the custody count
        custody_context.register_validator::<E>(vec![(8, 32_000_000_000)], Slot::new(0), &spec);
        assert_eq!(
            custody_context.custody_group_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement + 1,
            "head custody count should increase by 1"
        );

        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
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
            custody_context.custody_group_count(&spec),
            spec.validator_custody_requirement + spec.custody_requirement + 4,
            "head custody count should increase by 3"
        );

        assert_eq!(
            custody_context.advertised_custody_group_count(&spec),
            spec.custody_requirement,
            "advertised custody count should not change"
        );
    }
}

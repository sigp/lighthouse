use parking_lot::{lock_api::RwLock, RwLock};

use crate::{ChainSpec, Epoch};

// TODO(pawan): think more carefully about this number
pub const EPOCHS_BETWEEN_VALIDATOR_CUSTODY_UPDATES: usize = 10;

/// Specifies the validator custody requirements for the node based
/// on the number of validators attached to the beacon node.
#[derive(Debug, Eq, PartialOrd, Ord, Clone)]
pub enum ValidatorCustody {
    /// There are sufficient attached validators for the node to have to
    /// custody all the columns.
    ///
    /// Currently, we would need a minimum of 113 validators (32 ETH balance) attached to
    /// the node to custody all `NUMBER_OF_COLUMNS` columns.
    ///
    /// NUMBER_OF_COLUMNS - VALIDATOR_CUSTODY_REQUIREMENT - SAMPLES_PER_SLOT + 1
    ///  = 128 - 8 - 8 + 1 = 113
    AllColumns,
    /// All validator counts < 113.
    ///
    /// Note: A validator here refers to a 32 eth unit.
    NumValidators(usize),
    NoValidators,
}

impl ValidatorCustody {
    /// Generate the `ValidatorCustody` object based on a persisted value of the
    /// `cgc`.
    ///
    /// This cgc is the value that we get from the persisted metadata/enr.
    pub fn new_from_persisted_cgc(cgc: usize, spec: &ChainSpec) -> Self {
        // if cgc >= Self::min_validators_for_full_custody(spec) {
        //     Self::AllColumns
        // } else {
        //     Self::NumValidators(cgc)
        // }
        unimplemented!("todo(pawan)")
    }

    /// The minimum number of validators that need to be attached for
    /// the node to have to custody all columns.
    fn min_validators_for_full_custody(spec: &ChainSpec) -> usize {
        spec.number_of_columns - spec.validator_custody_requirement - spec.samples_per_slot + 1
    }

    /// Total number of columns to custody based on this validator count
    pub fn custody_count(&self, spec: &ChainSpec) -> usize {
        match self {
            Self::AllColumns => spec.number_of_columns,
            Self::NumValidators(count) => {
                if count == 0 {
                    0
                } else {
                    std::cmp::min(
                        spec.validator_custody_requirement + count - 1,
                        spec.number_of_columns,
                    )
                }
            }
        }
    }
}

/// Collects the various components for determining the custody count.
#[derive(Debug, Clone)]
pub struct CustodyCount {
    /// Columns to be custodied based on number of validators
    /// that is attached to this node.
    pub validator_custody: ValidatorCustody,
    /// Columns to be custodied based on the cli parameters passed by
    /// the user on startup.
    pub cli_custody_count: usize,
}

impl CustodyCount {
    /// The total number of columns that need to be custodied for a node with
    /// the given params.
    pub fn custody_columns_count(&self, spec: &ChainSpec) -> usize {
        std::cmp::min(
            self.cli_custody_count + self.validator_custody.custody_count(spec),
            spec.number_of_columns,
        )
    }
}

#[derive(Debug)]
pub struct CustodyContext {
    /// This is the `CustodyCount` object we are using to compute the
    /// cgc value that we advertise to our peers in our enr and metadata.
    advertised_custody: RwLock<CustodyCount>,
    /// This is the `CustodyCount` object that we use to perform sampling duties
    /// at head (while syncing or when receiving gossip).
    custody_at_head: RwLock<CustodyCount>,
    /// Updates to the number of validators that is attached to this node
    /// over a given time duration.
    /// TODO(pawan): make this a constant sized queue.
    validator_custody_updates: Vec<(Epoch, usize)>,
}

impl CustodyContext {
    /// Create a new custody default custody context object when no persisted object
    /// exists.
    pub fn new(cli_custody_count: usize, persisted_cgc: usize, spec: &ChainSpec) -> Self {
        let advertised_custody = CustodyCount {
            cli_custody_count,
            validator_custody: ValidatorCustody::NoValidators,
        };

        // The advertised custody and the custody object are the same when we
        // create an entirely new object.
        let custody_at_head = advertised_custody.clone();
        Self {
            advertised_custody: RwLock::new(advertised_custody),
            custody_at_head: RwLock::new(custody_at_head),
            validator_custody_updates: vec![],
        }
    }

    pub fn new_from_persisted_custody_context(bytes: &[u8]) -> Result<Self, String> {}

    /// The custody count that we advertise to our peers in our metadata and
    /// enr values.
    pub fn advertised_custody_column_count(&self, spec: &ChainSpec) -> usize {
        self.advertised_custody.read().custody_columns_count(spec)
    }

    /// The number of columns that we sample for the data availability check
    /// at the head of the chain.
    ///
    /// Use this function to get the custody count number for blocks received
    /// on gossip/rpc/sync.
    ///
    /// This value is essentially the internal `cgc` of the node.
    pub fn custody_column_count(&self, spec: &ChainSpec) -> usize {
        self.custody_at_head.read().custody_columns_count(spec)
    }
}

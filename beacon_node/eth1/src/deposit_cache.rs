use crate::{DepositLog, Eth1Block};
use ssz_derive::{Decode, Encode};
use state_processing::common::DepositDataTree;
use std::cmp::Ordering;
use superstruct::superstruct;
use tree_hash::TreeHash;
use types::{Deposit, DepositTreeSnapshot, Hash256, DEPOSIT_TREE_DEPTH};

#[derive(Debug, PartialEq)]
pub enum Error {
    /// A deposit log was added when a prior deposit was not already in the cache.
    ///
    /// Logs have to be added with monotonically-increasing block numbers.
    NonConsecutive { log_index: u64, expected: usize },
    /// The eth1 event log data was unable to be parsed.
    LogParse(String),
    /// There are insufficient deposits in the cache to fulfil the request.
    InsufficientDeposits {
        known_deposits: usize,
        requested: u64,
    },
    /// A log with the given index is already present in the cache and it does not match the one
    /// provided.
    DuplicateDistinctLog(u64),
    /// Attempted to insert log with given index after the log had been finalized
    FinalizedLogInsert {
        log_index: u64,
        finalized_index: u64,
    },
    /// The deposit count must always be large enough to account for the requested deposit range.
    ///
    /// E.g., you cannot request deposit 10 when the deposit count is 9.
    DepositCountInvalid { deposit_count: u64, range_end: u64 },
    /// You can't request deposits on or before the finalized deposit
    DepositRangeInvalid {
        range_start: u64,
        finalized_count: u64,
    },
    /// You can't finalize what's already been finalized and the cache must have the logs
    /// that you wish to finalize
    InvalidFinalizeIndex {
        requested_count: u64,
        currently_finalized: u64,
        deposit_count: u64,
    },
    /// Error with the merkle tree for deposits.
    DepositTree(merkle_proof::MerkleTreeError),
    /// An unexpected condition was encountered.
    Internal(String),
    /// This is for errors that should never occur
    PleaseNotifyTheDevs,
}

pub type SszDepositCache = SszDepositCacheV13;

#[superstruct(
    variants(V1, V13),
    variant_attributes(derive(Encode, Decode, Clone)),
    no_enum
)]
pub struct SszDepositCache {
    pub logs: Vec<DepositLog>,
    pub leaves: Vec<Hash256>,
    pub deposit_contract_deploy_block: u64,
    #[superstruct(only(V13))]
    pub finalized_deposit_count: u64,
    #[superstruct(only(V13))]
    pub finalized_block_height: u64,
    #[superstruct(only(V13))]
    pub deposit_tree_snapshot: Option<DepositTreeSnapshot>,
    pub deposit_roots: Vec<Hash256>,
}

impl SszDepositCache {
    pub fn from_deposit_cache(cache: &DepositCache) -> Self {
        Self {
            logs: cache.logs.clone(),
            leaves: cache.leaves.clone(),
            deposit_contract_deploy_block: cache.deposit_contract_deploy_block,
            finalized_deposit_count: cache.finalized_deposit_count,
            finalized_block_height: cache.finalized_block_height,
            deposit_tree_snapshot: cache.deposit_tree.get_snapshot(),
            deposit_roots: cache.deposit_roots.clone(),
        }
    }

    pub fn to_deposit_cache(&self) -> Result<DepositCache, String> {
        let deposit_tree = self
            .deposit_tree_snapshot
            .as_ref()
            .map(|snapshot| {
                let mut tree = DepositDataTree::from_snapshot(snapshot, DEPOSIT_TREE_DEPTH)
                    .map_err(|e| format!("Invalid SszDepositCache: {:?}", e))?;
                for leaf in &self.leaves {
                    tree.push_leaf(*leaf).map_err(|e| {
                        format!("Invalid SszDepositCache: unable to push leaf: {:?}", e)
                    })?;
                }
                Ok::<_, String>(tree)
            })
            .unwrap_or_else(|| {
                // deposit_tree_snapshot = None (tree was never finalized)
                // Create DepositDataTree from leaves
                Ok(DepositDataTree::create(
                    &self.leaves,
                    self.leaves.len(),
                    DEPOSIT_TREE_DEPTH,
                ))
            })?;

        // Check for invalid SszDepositCache conditions
        if self.leaves.len() != self.logs.len() {
            return Err("Invalid SszDepositCache: logs and leaves should have equal length".into());
        }
        // `deposit_roots` also includes the zero root
        if self.leaves.len() + 1 != self.deposit_roots.len() {
            return Err(
                "Invalid SszDepositCache: deposit_roots length must be only one more than leaves"
                    .into(),
            );
        }
        Ok(DepositCache {
            logs: self.logs.clone(),
            leaves: self.leaves.clone(),
            deposit_contract_deploy_block: self.deposit_contract_deploy_block,
            finalized_deposit_count: self.finalized_deposit_count,
            finalized_block_height: self.finalized_block_height,
            deposit_tree,
            deposit_roots: self.deposit_roots.clone(),
        })
    }
}

/// Mirrors the merkle tree of deposits in the eth1 deposit contract.
///
/// Provides `Deposit` objects with merkle proofs included.
#[cfg_attr(test, derive(PartialEq))]
pub struct DepositCache {
    logs: Vec<DepositLog>,
    leaves: Vec<Hash256>,
    deposit_contract_deploy_block: u64,
    finalized_deposit_count: u64,
    finalized_block_height: u64,
    /// An incremental merkle tree which represents the current state of the
    /// deposit contract tree.
    deposit_tree: DepositDataTree,
    /// Vector of deposit roots. `deposit_roots[i]` denotes `deposit_root` at
    /// `deposit_index` `i`.
    deposit_roots: Vec<Hash256>,
}

impl Default for DepositCache {
    fn default() -> Self {
        let deposit_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);
        let deposit_roots = vec![deposit_tree.root()];
        DepositCache {
            logs: Vec::new(),
            leaves: Vec::new(),
            deposit_contract_deploy_block: 1,
            finalized_deposit_count: 0,
            finalized_block_height: 0,
            deposit_tree,
            deposit_roots,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DepositCacheInsertOutcome {
    Inserted,
    Duplicate,
}

impl DepositCache {
    /// Create new `DepositCache` given block number at which deposit
    /// contract was deployed.
    pub fn new(deposit_contract_deploy_block: u64) -> Self {
        DepositCache {
            deposit_contract_deploy_block,
            finalized_block_height: deposit_contract_deploy_block.saturating_sub(1),
            ..Self::default()
        }
    }

    pub fn from_deposit_snapshot(
        deposit_contract_deploy_block: u64,
        snapshot: &DepositTreeSnapshot,
    ) -> Result<Self, String> {
        let deposit_tree = DepositDataTree::from_snapshot(snapshot, DEPOSIT_TREE_DEPTH)
            .map_err(|e| format!("Invalid DepositSnapshot: {:?}", e))?;
        Ok(DepositCache {
            logs: Vec::new(),
            leaves: Vec::new(),
            deposit_contract_deploy_block,
            finalized_deposit_count: snapshot.deposit_count,
            finalized_block_height: snapshot.execution_block_height,
            deposit_tree,
            deposit_roots: vec![snapshot.deposit_root],
        })
    }

    /// Returns the number of deposits the cache stores
    pub fn len(&self) -> usize {
        self.finalized_deposit_count as usize + self.logs.len()
    }

    /// True if the cache does not store any blocks.
    pub fn is_empty(&self) -> bool {
        self.finalized_deposit_count != 0 && self.logs.is_empty()
    }

    /// Returns the block number for the most recent deposit in the cache.
    pub fn latest_block_number(&self) -> u64 {
        self.logs
            .last()
            .map(|log| log.block_number)
            .unwrap_or(self.finalized_block_height)
    }

    /// Returns an iterator over all the logs in `self` that aren't finalized.
    pub fn iter(&self) -> impl Iterator<Item = &DepositLog> {
        self.logs.iter()
    }

    /// Returns the deposit log with INDEX i.
    pub fn get_log(&self, i: usize) -> Option<&DepositLog> {
        let finalized_deposit_count = self.finalized_deposit_count as usize;
        if i < finalized_deposit_count {
            None
        } else {
            self.logs.get(i - finalized_deposit_count)
        }
    }

    /// Returns the deposit root with DEPOSIT COUNT (not index) i
    pub fn get_root(&self, i: usize) -> Option<&Hash256> {
        let finalized_deposit_count = self.finalized_deposit_count as usize;
        if i < finalized_deposit_count {
            None
        } else {
            self.deposit_roots.get(i - finalized_deposit_count)
        }
    }

    /// Returns the finalized deposit count
    pub fn finalized_deposit_count(&self) -> u64 {
        self.finalized_deposit_count
    }

    /// Finalizes the cache up to `eth1_block.deposit_count`.
    pub fn finalize(&mut self, eth1_block: Eth1Block) -> Result<(), Error> {
        let deposits_to_finalize = eth1_block.deposit_count.ok_or_else(|| {
            Error::Internal("Eth1Block did not contain deposit_count".to_string())
        })?;

        let currently_finalized = self.finalized_deposit_count;
        if deposits_to_finalize > self.len() as u64 || deposits_to_finalize <= currently_finalized {
            Err(Error::InvalidFinalizeIndex {
                requested_count: deposits_to_finalize,
                currently_finalized,
                deposit_count: self.len() as u64,
            })
        } else {
            let finalized_log = self
                .get_log((deposits_to_finalize - 1) as usize)
                .cloned()
                .ok_or(Error::PleaseNotifyTheDevs)?;
            let drop = (deposits_to_finalize - currently_finalized) as usize;
            self.deposit_tree
                .finalize(eth1_block.into())
                .map_err(Error::DepositTree)?;
            self.logs.drain(0..drop);
            self.leaves.drain(0..drop);
            self.deposit_roots.drain(0..drop);
            self.finalized_deposit_count = deposits_to_finalize;
            self.finalized_block_height = finalized_log.block_number;

            Ok(())
        }
    }

    /// Returns the deposit tree snapshot (if tree is finalized)
    pub fn get_deposit_snapshot(&self) -> Option<DepositTreeSnapshot> {
        self.deposit_tree.get_snapshot()
    }

    /// Adds `log` to self.
    ///
    /// This function enforces that `logs` are imported one-by-one with no gaps between
    /// `log.index`, starting at `log.index == 0`.
    ///
    /// ## Errors
    ///
    /// - If a log with index `log.index - 1` is not already present in `self` (ignored when empty).
    /// - If a log with `log.index` is already known, but the given `log` is distinct to it.
    pub fn insert_log(&mut self, log: DepositLog) -> Result<DepositCacheInsertOutcome, Error> {
        match log.index.cmp(&(self.len() as u64)) {
            Ordering::Equal => {
                let deposit = log.deposit_data.tree_hash_root();
                // should push to deposit_tree first because it's fallible
                self.deposit_tree
                    .push_leaf(deposit)
                    .map_err(Error::DepositTree)?;
                self.leaves.push(deposit);
                self.logs.push(log);
                self.deposit_roots.push(self.deposit_tree.root());
                Ok(DepositCacheInsertOutcome::Inserted)
            }
            Ordering::Less => {
                let mut compare_index = log.index as usize;
                if log.index < self.finalized_deposit_count {
                    return Err(Error::FinalizedLogInsert {
                        log_index: log.index,
                        finalized_index: self.finalized_deposit_count - 1,
                    });
                } else {
                    compare_index -= self.finalized_deposit_count as usize;
                }
                if self.logs[compare_index] == log {
                    Ok(DepositCacheInsertOutcome::Duplicate)
                } else {
                    Err(Error::DuplicateDistinctLog(log.index))
                }
            }
            Ordering::Greater => Err(Error::NonConsecutive {
                log_index: log.index,
                expected: self.logs.len(),
            }),
        }
    }

    /// Returns a list of `Deposit` objects, within the given deposit index `range`.
    ///
    /// The `deposit_count` is used to generate the proofs for the `Deposits`. For example, if we
    /// have 100 proofs, but the eth2 chain only acknowledges 50 of them, we must produce our
    /// proofs with respect to a tree size of 50.
    ///
    ///
    /// ## Errors
    ///
    /// - If `deposit_count` is less than `end`.
    /// - There are not sufficient deposits in the tree to generate the proof.
    pub fn get_deposits(
        &self,
        start: u64,
        end: u64,
        deposit_count: u64,
    ) -> Result<(Hash256, Vec<Deposit>), Error> {
        if deposit_count < end {
            // It's invalid to ask for more deposits than should exist.
            Err(Error::DepositCountInvalid {
                deposit_count,
                range_end: end,
            })
        } else if end > self.len() as u64 {
            // The range of requested deposits exceeds the deposits stored locally.
            Err(Error::InsufficientDeposits {
                requested: end,
                known_deposits: self.logs.len(),
            })
        } else if self.finalized_deposit_count > start {
            // Can't ask for deposits before or on the finalized deposit
            Err(Error::DepositRangeInvalid {
                range_start: start,
                finalized_count: self.finalized_deposit_count,
            })
        } else {
            let (start, end, deposit_count) = (
                start - self.finalized_deposit_count,
                end - self.finalized_deposit_count,
                deposit_count - self.finalized_deposit_count,
            );
            let leaves = self
                .leaves
                .get(0..deposit_count as usize)
                .ok_or_else(|| Error::Internal("Unable to get known leaves".into()))?;

            let tree = self
                .deposit_tree
                .get_snapshot()
                .map(|snapshot| {
                    // The tree has already been finalized. So we can just start from the snapshot
                    // and replay the deposits up to `deposit_count`
                    let mut tree = DepositDataTree::from_snapshot(&snapshot, DEPOSIT_TREE_DEPTH)
                        .map_err(Error::DepositTree)?;
                    for leaf in leaves {
                        tree.push_leaf(*leaf).map_err(Error::DepositTree)?;
                    }
                    Ok(tree)
                })
                .unwrap_or_else(|| {
                    // Deposit tree hasn't been finalized yet, will have to re-create the whole tree
                    Ok(DepositDataTree::create(
                        leaves,
                        leaves.len(),
                        DEPOSIT_TREE_DEPTH,
                    ))
                })?;

            let mut deposits = vec![];
            self.logs
                .get(start as usize..end as usize)
                .ok_or_else(|| Error::Internal("Unable to get known log".into()))?
                .iter()
                .try_for_each(|deposit_log| {
                    let (_leaf, proof) = tree
                        .generate_proof(deposit_log.index as usize)
                        .map_err(Error::DepositTree)?;
                    deposits.push(Deposit {
                        proof: proof.into(),
                        data: deposit_log.deposit_data.clone(),
                    });
                    Ok(())
                })?;

            Ok((tree.root(), deposits))
        }
    }

    /// Returns the number of deposits with valid signatures that have been observed up to and
    /// including the block at `block_number`.
    ///
    /// Returns `None` if the `block_number` is zero or prior to contract deployment.
    pub fn get_valid_signature_count(&self, block_number: u64) -> Option<usize> {
        if block_number == 0 || block_number < self.deposit_contract_deploy_block {
            None
        } else {
            Some(
                self.logs
                    .iter()
                    .take_while(|deposit| deposit.block_number <= block_number)
                    .filter(|deposit| deposit.signature_is_valid)
                    .count(),
            )
        }
    }

    /// Returns the number of deposits that have been observed up to and
    /// including the block at `block_number`.
    ///
    /// Returns `None` if the `block_number` is zero or prior to contract deployment
    /// or prior to last finalized deposit.
    pub fn get_deposit_count_from_cache(&self, block_number: u64) -> Option<u64> {
        if block_number == 0
            || block_number < self.deposit_contract_deploy_block
            || block_number < self.finalized_block_height
        {
            None
        } else if block_number == self.finalized_block_height {
            Some(self.finalized_deposit_count)
        } else {
            Some(
                self.finalized_deposit_count
                    + self
                        .logs
                        .iter()
                        .take_while(|deposit| deposit.block_number <= block_number)
                        .count() as u64,
            )
        }
    }

    /// Gets the deposit root at block height = block_number.
    ///
    /// Fetches the `deposit_count` on or just before the queried `block_number`
    /// and queries the `deposit_roots` map to get the corresponding `deposit_root`.
    pub fn get_deposit_root_from_cache(&self, block_number: u64) -> Option<Hash256> {
        let count = self.get_deposit_count_from_cache(block_number)?;
        self.get_root(count as usize).cloned()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use execution_layer::http::deposit_log::Log;
    use types::{EthSpec, MainnetEthSpec};

    /// The data from a deposit event, using the v0.8.3 version of the deposit contract.
    pub const EXAMPLE_LOG: &[u8] = &[
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 167, 108, 6, 69, 88, 17, 3, 51, 6, 4, 158, 232, 82,
        248, 218, 2, 71, 219, 55, 102, 86, 125, 136, 203, 36, 77, 64, 213, 43, 52, 175, 154, 239,
        50, 142, 52, 201, 77, 54, 239, 0, 229, 22, 46, 139, 120, 62, 240, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 64, 89, 115, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 140, 74, 175, 158, 209, 20, 206,
        30, 63, 215, 238, 113, 60, 132, 216, 211, 100, 186, 202, 71, 34, 200, 160, 225, 212, 213,
        119, 88, 51, 80, 101, 74, 2, 45, 78, 153, 12, 192, 44, 51, 77, 40, 10, 72, 246, 34, 193,
        187, 22, 95, 4, 211, 245, 224, 13, 162, 21, 163, 54, 225, 22, 124, 3, 56, 14, 81, 122, 189,
        149, 250, 251, 159, 22, 77, 94, 157, 197, 196, 253, 110, 201, 88, 193, 246, 136, 226, 221,
        18, 113, 232, 105, 100, 114, 103, 237, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    fn example_log() -> DepositLog {
        let spec = MainnetEthSpec::default_spec();

        let log = Log {
            block_number: 42,
            data: EXAMPLE_LOG.to_vec(),
        };
        log.to_deposit_log(&spec).expect("should decode log")
    }

    fn get_cache_with_deposits(n: u64) -> DepositCache {
        let mut deposit_cache = DepositCache::default();
        for i in 0..n {
            let mut log = example_log();
            log.index = i;
            log.block_number = i;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i);
            deposit_cache
                .insert_log(log)
                .expect("should add consecutive logs");
        }
        assert_eq!(deposit_cache.len() as u64, n, "should have {} deposits", n);

        deposit_cache
    }

    #[test]
    fn insert_log_valid() {
        let mut deposit_cache = DepositCache::default();

        for i in 0..16 {
            let mut log = example_log();
            log.index = i;
            deposit_cache
                .insert_log(log)
                .expect("should add consecutive logs");
        }
    }

    #[test]
    fn insert_log_invalid() {
        let mut deposit_cache = DepositCache::default();

        for i in 0..4 {
            let mut log = example_log();
            log.index = i;
            deposit_cache
                .insert_log(log)
                .expect("should add consecutive logs");
        }

        // Add duplicate, when given is the same as the one known.
        let mut log = example_log();
        log.index = 3;
        assert_eq!(
            deposit_cache.insert_log(log).unwrap(),
            DepositCacheInsertOutcome::Duplicate
        );

        // Add duplicate, when given is different to the one known.
        let mut log = example_log();
        log.index = 3;
        log.block_number = 99;
        assert!(deposit_cache.insert_log(log).is_err());

        //  Skip inserting a log.
        let mut log = example_log();
        log.index = 5;
        assert!(deposit_cache.insert_log(log).is_err());
    }

    #[test]
    fn get_deposit_valid() {
        let n = 1_024;
        let deposit_cache = get_cache_with_deposits(n);

        // Get 0 deposits, with max deposit count.
        let (_, deposits) = deposit_cache
            .get_deposits(0, 0, n)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get 0 deposits, with 0 deposit count.
        let (_, deposits) = deposit_cache
            .get_deposits(0, 0, 0)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get all deposits, with max deposit count.
        let (full_root, deposits) = deposit_cache
            .get_deposits(0, n, n)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), n as usize, "should return all deposits");

        // Get 4 deposits, with max deposit count.
        let (root, deposits) = deposit_cache
            .get_deposits(0, 4, n)
            .expect("should get the four from the full tree");
        assert_eq!(
            deposits.len(),
            4_usize,
            "should get 4 deposits from full tree"
        );
        assert_eq!(
            root, full_root,
            "should still return full root when getting deposit subset"
        );

        // Get half of the deposits, with half deposit count.
        let half = n / 2;
        let (half_root, deposits) = deposit_cache
            .get_deposits(0, half, half)
            .expect("should get the half tree");
        assert_eq!(deposits.len(), half as usize, "should return half deposits");

        // Get 4 deposits, with half deposit count.
        let (root, deposits) = deposit_cache
            .get_deposits(0, 4, n / 2)
            .expect("should get the half tree");
        assert_eq!(
            deposits.len(),
            4_usize,
            "should get 4 deposits from half tree"
        );
        assert_eq!(
            root, half_root,
            "should still return half root when getting deposit subset"
        );
        assert_ne!(
            full_root, half_root,
            "should get different root when pinning deposit count"
        );
    }

    #[test]
    fn get_deposit_invalid() {
        let n = 16;
        let mut tree = get_cache_with_deposits(n);

        // Range too high.
        assert!(tree.get_deposits(0, n + 1, n).is_err());

        // Count too high.
        assert!(tree.get_deposits(0, n, n + 1).is_err());

        // Range higher than count.
        assert!(tree.get_deposits(0, 4, 2).is_err());

        let block7 = fake_eth1_block(&tree, 7).expect("should create fake eth1 block");
        tree.finalize(block7).expect("should finalize");
        // Range starts <= finalized deposit
        assert!(tree.get_deposits(6, 9, 11).is_err());
        assert!(tree.get_deposits(7, 9, 11).is_err());
        // Range start > finalized deposit should be OK
        assert!(tree.get_deposits(8, 9, 11).is_ok());
    }

    // returns an eth1 block that can be used to finalize the cache at `deposit_index`
    // this will ensure the `deposit_root` on the `Eth1Block` is correct
    fn fake_eth1_block(deposit_cache: &DepositCache, deposit_index: usize) -> Option<Eth1Block> {
        let deposit_log = deposit_cache.get_log(deposit_index)?;
        Some(Eth1Block {
            hash: Hash256::from_low_u64_be(deposit_log.block_number),
            timestamp: 0,
            number: deposit_log.block_number,
            deposit_root: deposit_cache.get_root(deposit_index + 1).cloned(),
            deposit_count: Some(deposit_log.index + 1),
        })
    }

    #[test]
    fn test_finalization_boundaries() {
        let n = 8;
        let half = (n / 2) as usize;

        let mut deposit_cache = get_cache_with_deposits(n as u64);

        let full_root_before_finalization = deposit_cache.deposit_tree.root();
        let half_log_plus1_before_finalization = deposit_cache
            .get_log(half + 1)
            .expect("log should exist")
            .clone();
        let half_root_plus1_before_finalization =
            *deposit_cache.get_root(half + 1).expect("root should exist");

        let (root_before_finalization, proof_before_finalization) = deposit_cache
            .get_deposits((half + 1) as u64, (half + 2) as u64, (half + 2) as u64)
            .expect("should return 1 deposit with proof");

        // finalize on the tree at half
        let half_block =
            fake_eth1_block(&deposit_cache, half).expect("fake block should be created");
        assert!(
            deposit_cache.get_deposit_snapshot().is_none(),
            "snapshot should  not exist as tree has not been finalized"
        );
        deposit_cache
            .finalize(half_block)
            .expect("tree should_finalize");

        // check boundary conditions for get_log
        assert!(
            deposit_cache.get_log(half).is_none(),
            "log at finalized deposit should NOT exist"
        );
        assert_eq!(
            *deposit_cache.get_log(half + 1).expect("log should exist"),
            half_log_plus1_before_finalization,
            "log after finalized deposit should match before finalization"
        );
        // check boundary conditions for get_root
        assert!(
            deposit_cache.get_root(half).is_none(),
            "root at finalized deposit should NOT exist"
        );
        assert_eq!(
            *deposit_cache.get_root(half + 1).expect("root should exist"),
            half_root_plus1_before_finalization,
            "root after finalized deposit should match before finalization"
        );
        // full root should match before and after finalization
        assert_eq!(
            deposit_cache.deposit_tree.root(),
            full_root_before_finalization,
            "full root should match before and after finalization"
        );
        // check boundary conditions for get_deposits (proof)
        assert!(
            deposit_cache
                .get_deposits(half as u64, (half + 1) as u64, (half + 1) as u64)
                .is_err(),
            "cannot prove the finalized deposit"
        );
        let (root_after_finalization, proof_after_finalization) = deposit_cache
            .get_deposits((half + 1) as u64, (half + 2) as u64, (half + 2) as u64)
            .expect("should return 1 deposit with proof");
        assert_eq!(
            root_before_finalization, root_after_finalization,
            "roots before and after finalization should match"
        );
        assert_eq!(
            proof_before_finalization, proof_after_finalization,
            "proof before and after finalization should match"
        );

        // recover tree from snapshot by replaying deposits
        let snapshot = deposit_cache
            .get_deposit_snapshot()
            .expect("snapshot should exist");
        let mut recovered = DepositCache::from_deposit_snapshot(1, &snapshot)
            .expect("should recover finalized tree");
        for i in half + 1..n {
            let mut log = example_log();
            log.index = i as u64;
            log.block_number = i as u64;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i as u64);
            recovered
                .insert_log(log)
                .expect("should add consecutive logs");
        }

        // check the same boundary conditions above for the recovered tree
        assert!(
            recovered.get_log(half).is_none(),
            "log at finalized deposit should NOT exist"
        );
        assert_eq!(
            *recovered.get_log(half + 1).expect("log should exist"),
            half_log_plus1_before_finalization,
            "log after finalized deposit should match before finalization in recovered tree"
        );
        // check boundary conditions for get_root
        assert!(
            recovered.get_root(half).is_none(),
            "root at finalized deposit should NOT exist"
        );
        assert_eq!(
            *recovered.get_root(half + 1).expect("root should exist"),
            half_root_plus1_before_finalization,
            "root after finalized deposit should match before finalization in recovered tree"
        );
        // full root should match before and after finalization
        assert_eq!(
            recovered.deposit_tree.root(),
            full_root_before_finalization,
            "full root should match before and after finalization"
        );
        // check boundary conditions for get_deposits (proof)
        assert!(
            recovered
                .get_deposits(half as u64, (half + 1) as u64, (half + 1) as u64)
                .is_err(),
            "cannot prove the finalized deposit"
        );
        let (recovered_root_after_finalization, recovered_proof_after_finalization) = recovered
            .get_deposits((half + 1) as u64, (half + 2) as u64, (half + 2) as u64)
            .expect("should return 1 deposit with proof");
        assert_eq!(
            root_before_finalization, recovered_root_after_finalization,
            "recovered roots before and after finalization should match"
        );
        assert_eq!(
            proof_before_finalization, recovered_proof_after_finalization,
            "recovered proof before and after finalization should match"
        );
    }

    #[test]
    fn test_finalization() {
        let n = 1024;
        let half = n / 2;
        let quarter = half / 2;
        let mut deposit_cache = get_cache_with_deposits(n);

        let full_root_before_finalization = deposit_cache.deposit_tree.root();
        let q3_root_before_finalization = deposit_cache
            .get_root((half + quarter) as usize)
            .cloned()
            .expect("root should exist");
        let q3_log_before_finalization = deposit_cache
            .get_log((half + quarter) as usize)
            .cloned()
            .expect("log should exist");
        // get_log(half+quarter) should return log with index `half+quarter`
        assert_eq!(
            q3_log_before_finalization.index,
            (half + quarter) as u64,
            "log index should be {}",
            (half + quarter),
        );

        // get lower quarter of deposits with max deposit count
        let (lower_quarter_root_before_finalization, lower_quarter_deposits_before_finalization) =
            deposit_cache
                .get_deposits(quarter, half, n)
                .expect("should get lower quarter");
        assert_eq!(
            lower_quarter_deposits_before_finalization.len(),
            quarter as usize,
            "should get {} deposits from lower quarter",
            quarter,
        );
        // since the lower quarter was done with full deposits, root should be the same as full_root_before_finalization
        assert_eq!(
            lower_quarter_root_before_finalization, full_root_before_finalization,
            "should still get full root with deposit subset",
        );

        // get upper quarter of deposits with slightly reduced deposit count
        let (upper_quarter_root_before_finalization, upper_quarter_deposits_before_finalization) =
            deposit_cache
                .get_deposits(half, half + quarter, n - 2)
                .expect("should get upper quarter");
        assert_eq!(
            upper_quarter_deposits_before_finalization.len(),
            quarter as usize,
            "should get {} deposits from upper quarter",
            quarter,
        );
        // since upper quarter was with subset of nodes, it should differ from full root
        assert_ne!(
            full_root_before_finalization, upper_quarter_root_before_finalization,
            "subtree root should differ from full root",
        );

        let f0_log = deposit_cache
            .get_log((quarter - 1) as usize)
            .cloned()
            .expect("should return log");
        let f0_block = fake_eth1_block(&deposit_cache, (quarter - 1) as usize)
            .expect("fake eth1 block should be created");

        // finalize first quarter
        deposit_cache
            .finalize(f0_block)
            .expect("should finalize first quarter");
        // finalized count and block number should match log
        assert_eq!(
            deposit_cache.finalized_deposit_count,
            f0_log.index + 1,
            "after calling finalize(eth1block) finalized_deposit_count should equal eth1_block.deposit_count",
        );
        assert_eq!(
            deposit_cache.finalized_block_height,
            f0_log.block_number,
            "after calling finalize(eth1block) finalized_block_number should equal eth1block.block_number"
        );
        // check get_log boundaries
        assert!(
            deposit_cache.get_log((quarter - 1) as usize).is_none(),
            "get_log() should return None for index <= finalized log index",
        );
        assert!(
            deposit_cache.get_log(quarter as usize).is_some(),
            "get_log() should return Some(log) for index >= finalized_deposit_count",
        );

        // full root should remain the same after finalization
        assert_eq!(
            full_root_before_finalization,
            deposit_cache.deposit_tree.root(),
            "root should be the same before and after finalization",
        );
        // get_root should return the same root before and after finalization
        assert_eq!(
            q3_root_before_finalization,
            deposit_cache
                .get_root((half + quarter) as usize)
                .cloned()
                .expect("root should exist"),
            "get_root should return the same root before and after finalization",
        );
        // get_log should return the same log before and after finalization
        assert_eq!(
            q3_log_before_finalization,
            deposit_cache
                .get_log((half + quarter) as usize)
                .cloned()
                .expect("log should exist"),
            "get_log should return the same log before and after finalization",
        );

        // again get lower quarter of deposits with max deposit count after finalization
        let (f0_lower_quarter_root, f0_lower_quarter_deposits) = deposit_cache
            .get_deposits(quarter, half, n)
            .expect("should get lower quarter");
        assert_eq!(
            f0_lower_quarter_deposits.len(),
            quarter as usize,
            "should get {} deposits from lower quarter",
            quarter,
        );
        // again get upper quarter of deposits with slightly reduced deposit count after finalization
        let (f0_upper_quarter_root, f0_upper_quarter_deposits) = deposit_cache
            .get_deposits(half, half + quarter, n - 2)
            .expect("should get upper quarter");
        assert_eq!(
            f0_upper_quarter_deposits.len(),
            quarter as usize,
            "should get {} deposits from upper quarter",
            quarter,
        );

        // lower quarter root and deposits should be the same
        assert_eq!(
            lower_quarter_root_before_finalization, f0_lower_quarter_root,
            "root should be the same before and after finalization",
        );
        for i in 0..lower_quarter_deposits_before_finalization.len() {
            assert_eq!(
                lower_quarter_deposits_before_finalization[i], f0_lower_quarter_deposits[i],
                "get_deposits() should be the same before and after finalization",
            );
        }
        // upper quarter root and deposits should be the same
        assert_eq!(
            upper_quarter_root_before_finalization, f0_upper_quarter_root,
            "subtree root should be the same before and after finalization",
        );
        for i in 0..upper_quarter_deposits_before_finalization.len() {
            assert_eq!(
                upper_quarter_deposits_before_finalization[i], f0_upper_quarter_deposits[i],
                "get_deposits() should be the same before and after finalization",
            );
        }

        let f1_log = deposit_cache
            .get_log((half - 2) as usize)
            .cloned()
            .expect("should return log");
        // finalize a little less than half to test multiple finalization
        let f1_block = fake_eth1_block(&deposit_cache, (half - 2) as usize)
            .expect("should create fake eth1 block");
        deposit_cache
            .finalize(f1_block)
            .expect("should finalize a little less than half");
        // finalized count and block number should match f1_log
        assert_eq!(
            deposit_cache.finalized_deposit_count,
            f1_log.index + 1,
            "after calling finalize(eth1block) finalized_deposit_count should equal eth1_block.deposit_count",
        );
        assert_eq!(
            deposit_cache.finalized_block_height,
            f1_log.block_number,
            "after calling finalize(eth1block) finalized_block_number should equal eth1block.block_number"
        );
        // check get_log boundaries
        assert!(
            deposit_cache.get_log((half - 2) as usize).is_none(),
            "get_log() should return None for index <= finalized log index",
        );
        assert!(
            deposit_cache.get_log((half - 1) as usize).is_some(),
            "get_log() should return Some(log) for index >= finalized_deposit_count",
        );

        // full root should still be unchanged
        assert_eq!(
            full_root_before_finalization,
            deposit_cache.deposit_tree.root(),
            "root should be the same before and after finalization",
        );

        // again get upper quarter of deposits with slightly reduced deposit count after second finalization
        let (f1_upper_quarter_root, f1_upper_quarter_deposits) = deposit_cache
            .get_deposits(half, half + quarter, n - 2)
            .expect("should get upper quarter");

        // upper quarter root and deposits should be the same after second finalization
        assert_eq!(
            f0_upper_quarter_root, f1_upper_quarter_root,
            "subtree root should be the same after multiple finalization",
        );
        for i in 0..f0_upper_quarter_deposits.len() {
            assert_eq!(
                f0_upper_quarter_deposits[i], f1_upper_quarter_deposits[i],
                "get_deposits() should be the same before and after finalization",
            );
        }
    }

    fn verify_equality(original: &DepositCache, copy: &DepositCache) {
        // verify each field individually so that if one field should
        // fail to recover, this test will point right to it
        assert_eq!(original.deposit_contract_deploy_block, copy.deposit_contract_deploy_block, "DepositCache: deposit_contract_deploy_block should remain the same after encoding and decoding from ssz" );
        assert_eq!(
            original.leaves, copy.leaves,
            "DepositCache: leaves should remain the same after encoding and decoding from ssz"
        );
        assert_eq!(
            original.logs, copy.logs,
            "DepositCache: logs should remain the same after encoding and decoding from ssz"
        );
        assert_eq!(original.finalized_deposit_count, copy.finalized_deposit_count, "DepositCache: finalized_deposit_count should remain the same after encoding and decoding from ssz");
        assert_eq!(original.finalized_block_height, copy.finalized_block_height, "DepositCache: finalized_block_height should remain the same after encoding and decoding from ssz");
        assert_eq!(original.deposit_roots, copy.deposit_roots, "DepositCache: deposit_roots should remain the same before and after encoding and decoding from ssz");
        assert!(original.deposit_tree == copy.deposit_tree, "DepositCache: deposit_tree should remain the same before and after encoding and decoding from ssz");
        // verify all together for good measure
        assert!(
            original == copy,
            "Deposit cache should remain the same after encoding and decoding from ssz"
        );
    }

    fn ssz_round_trip(original: &DepositCache) -> DepositCache {
        use ssz::{Decode, Encode};
        let bytes = SszDepositCache::from_deposit_cache(original).as_ssz_bytes();
        let ssz_cache =
            SszDepositCache::from_ssz_bytes(&bytes).expect("should decode from ssz bytes");

        SszDepositCache::to_deposit_cache(&ssz_cache).expect("should recover cache")
    }

    #[test]
    fn ssz_encode_decode() {
        let deposit_cache = get_cache_with_deposits(512);
        let recovered_cache = ssz_round_trip(&deposit_cache);

        verify_equality(&deposit_cache, &recovered_cache);
    }

    #[test]
    fn ssz_encode_decode_with_finalization() {
        let mut deposit_cache = get_cache_with_deposits(512);
        let block383 = fake_eth1_block(&deposit_cache, 383).expect("should create fake eth1 block");
        deposit_cache.finalize(block383).expect("should finalize");
        let mut first_recovery = ssz_round_trip(&deposit_cache);

        verify_equality(&deposit_cache, &first_recovery);
        // finalize again to verify equality after multiple finalizations
        let block447 = fake_eth1_block(&deposit_cache, 447).expect("should create fake eth1 block");
        first_recovery.finalize(block447).expect("should finalize");

        let mut second_recovery = ssz_round_trip(&first_recovery);
        verify_equality(&first_recovery, &second_recovery);

        // verify equality of a tree that finalized block383, block447, block479
        // with a tree that finalized block383, block479
        let block479 = fake_eth1_block(&deposit_cache, 479).expect("should create fake eth1 block");
        second_recovery
            .finalize(block479.clone())
            .expect("should finalize");
        let third_recovery = ssz_round_trip(&second_recovery);
        deposit_cache.finalize(block479).expect("should finalize");

        verify_equality(&deposit_cache, &third_recovery);
    }
}

use crate::DepositLog;
use eth2_hashing::hash;
use tree_hash::TreeHash;
use types::{Deposit, Hash256};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// A deposit log was added when a prior deposit was not already in the cache.
    ///
    /// Logs have to be added with monotonically-increasing block numbers.
    NonConsecutive { log_index: u64, expected: usize },
    /// The eth1 event log data was unable to be parsed.
    LogParseError(String),
    /// There are insufficient deposits in the cache to fulfil the request.
    InsufficientDeposits {
        known_deposits: usize,
        requested: u64,
    },
    /// A log with the given index is already present in the cache and it does not match the one
    /// provided.
    DuplicateDistinctLog(u64),
    /// The deposit count must always be large enough to account for the requested deposit range.
    ///
    /// E.g., you cannot request deposit 10 when the deposit count is 9.
    DepositCountInvalid { deposit_count: u64, range_end: u64 },
    /// An unexpected condition was encountered.
    InternalError(String),
}

/// Emulates the eth1 deposit contract merkle tree.
pub struct DepositDataTree {
    tree: merkle_proof::MerkleTree,
    mix_in_length: usize,
    depth: usize,
}

impl DepositDataTree {
    /// Create a new Merkle tree from a list of leaves (`DepositData::tree_hash_root`) and a fixed depth.
    pub fn create(leaves: &[Hash256], mix_in_length: usize, depth: usize) -> Self {
        Self {
            tree: merkle_proof::MerkleTree::create(leaves, depth),
            mix_in_length,
            depth,
        }
    }

    /// Returns 32 bytes representing the "mix in length" for the merkle root of this tree.
    fn length_bytes(&self) -> Vec<u8> {
        int_to_bytes32(self.mix_in_length)
    }

    /// Retrieve the root hash of this Merkle tree with the length mixed in.
    pub fn root(&self) -> Hash256 {
        let mut preimage = [0; 64];
        preimage[0..32].copy_from_slice(&self.tree.hash()[..]);
        preimage[32..64].copy_from_slice(&self.length_bytes());
        Hash256::from_slice(&hash(&preimage))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth + 1`.
    pub fn generate_proof(&self, index: usize) -> (Hash256, Vec<Hash256>) {
        let (root, mut proof) = self.tree.generate_proof(index, self.depth);
        proof.push(Hash256::from_slice(&self.length_bytes()));
        (root, proof)
    }
}

/// Mirrors the merkle tree of deposits in the eth1 deposit contract.
///
/// Provides `Deposit` objects with merkle proofs included.
#[derive(Default)]
pub struct DepositCache {
    logs: Vec<DepositLog>,
    roots: Vec<Hash256>,
}

impl DepositCache {
    /// Returns the number of deposits available in the cache.
    pub fn len(&self) -> usize {
        self.logs.len()
    }

    /// True if the cache does not store any blocks.
    pub fn is_empty(&self) -> bool {
        self.logs.is_empty()
    }

    /// Returns the block number for the most recent deposit in the cache.
    pub fn latest_block_number(&self) -> Option<u64> {
        self.logs.last().map(|log| log.block_number)
    }

    /// Returns an iterator over all the logs in `self`.
    pub fn iter(&self) -> impl Iterator<Item = &DepositLog> {
        self.logs.iter()
    }

    /// Returns the i'th deposit log.
    pub fn get(&self, i: usize) -> Option<&DepositLog> {
        self.logs.get(i)
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
    pub fn insert_log(&mut self, log: DepositLog) -> Result<(), Error> {
        if log.index == self.logs.len() as u64 {
            self.roots
                .push(Hash256::from_slice(&log.deposit_data.tree_hash_root()));
            self.logs.push(log);

            Ok(())
        } else if log.index < self.logs.len() as u64 {
            if self.logs[log.index as usize] == log {
                Ok(())
            } else {
                Err(Error::DuplicateDistinctLog(log.index))
            }
        } else {
            Err(Error::NonConsecutive {
                log_index: log.index,
                expected: self.logs.len(),
            })
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
    /// - If `deposit_count` is larger than `end`.
    /// - There are not sufficient deposits in the tree to generate the proof.
    pub fn get_deposits(
        &self,
        start: u64,
        end: u64,
        deposit_count: u64,
        tree_depth: usize,
    ) -> Result<(Hash256, Vec<Deposit>), Error> {
        if deposit_count < end {
            // It's invalid to ask for more deposits than should exist.
            Err(Error::DepositCountInvalid {
                deposit_count,
                range_end: end,
            })
        } else if end > self.logs.len() as u64 {
            // The range of requested deposits exceeds the deposits stored locally.
            Err(Error::InsufficientDeposits {
                requested: end,
                known_deposits: self.logs.len(),
            })
        } else if deposit_count > self.roots.len() as u64 {
            // There are not `deposit_count` known deposit roots, so we can't build the merkle tree
            // to prove into.
            Err(Error::InsufficientDeposits {
                requested: deposit_count,
                known_deposits: self.logs.len(),
            })
        } else {
            let roots = self
                .roots
                .get(0..deposit_count as usize)
                .ok_or_else(|| Error::InternalError("Unable to get known root".into()))?;

            // Note: there is likely a more optimal solution than recreating the `DepositDataTree`
            // each time this function is called.
            //
            // Perhaps a base merkle tree could be maintained that contains all deposits up to the
            // last finalized eth1 deposit count. Then, that tree could be cloned and extended for
            // each of these calls.

            let tree = DepositDataTree::create(roots, deposit_count as usize, tree_depth);

            let deposits = self
                .logs
                .get(start as usize..end as usize)
                .ok_or_else(|| Error::InternalError("Unable to get known log".into()))?
                .iter()
                .map(|deposit_log| {
                    let (_leaf, proof) = tree.generate_proof(deposit_log.index as usize);

                    Deposit {
                        proof: proof.into(),
                        data: deposit_log.deposit_data.clone(),
                    }
                })
                .collect();

            Ok((tree.root(), deposits))
        }
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: usize) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::deposit_log::tests::EXAMPLE_LOG;
    use crate::http::Log;

    pub const TREE_DEPTH: usize = 32;

    fn example_log() -> DepositLog {
        let log = Log {
            block_number: 42,
            data: EXAMPLE_LOG.to_vec(),
        };
        DepositLog::from_log(&log).expect("should decode log")
    }

    #[test]
    fn insert_log_valid() {
        let mut tree = DepositCache::default();

        for i in 0..16 {
            let mut log = example_log();
            log.index = i;
            tree.insert_log(log).expect("should add consecutive logs")
        }
    }

    #[test]
    fn insert_log_invalid() {
        let mut tree = DepositCache::default();

        for i in 0..4 {
            let mut log = example_log();
            log.index = i;
            tree.insert_log(log).expect("should add consecutive logs")
        }

        // Add duplicate, when given is the same as the one known.
        let mut log = example_log();
        log.index = 3;
        assert!(tree.insert_log(log).is_ok());

        // Add duplicate, when given is different to the one known.
        let mut log = example_log();
        log.index = 3;
        log.block_number = 99;
        assert!(tree.insert_log(log).is_err());

        //  Skip inserting a log.
        let mut log = example_log();
        log.index = 5;
        assert!(tree.insert_log(log).is_err());
    }

    #[test]
    fn get_deposit_valid() {
        let n = 1_024;
        let mut tree = DepositCache::default();

        for i in 0..n {
            let mut log = example_log();
            log.index = i;
            log.block_number = i;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i);
            tree.insert_log(log).expect("should add consecutive logs")
        }

        // Get 0 deposits, with max deposit count.
        let (_, deposits) = tree
            .get_deposits(0, 0, n, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get 0 deposits, with 0 deposit count.
        let (_, deposits) = tree
            .get_deposits(0, 0, 0, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get 0 deposits, with 0 deposit count, tree depth 0.
        let (_, deposits) = tree
            .get_deposits(0, 0, 0, 0)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get all deposits, with max deposit count.
        let (full_root, deposits) = tree
            .get_deposits(0, n, n, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), n as usize, "should return all deposits");

        // Get 4 deposits, with max deposit count.
        let (root, deposits) = tree
            .get_deposits(0, 4, n, TREE_DEPTH)
            .expect("should get the four from the full tree");
        assert_eq!(
            deposits.len(),
            4 as usize,
            "should get 4 deposits from full tree"
        );
        assert_eq!(
            root, full_root,
            "should still return full root when getting deposit subset"
        );

        // Get half of the deposits, with half deposit count.
        let half = n / 2;
        let (half_root, deposits) = tree
            .get_deposits(0, half, half, TREE_DEPTH)
            .expect("should get the half tree");
        assert_eq!(deposits.len(), half as usize, "should return half deposits");

        // Get 4 deposits, with half deposit count.
        let (root, deposits) = tree
            .get_deposits(0, 4, n / 2, TREE_DEPTH)
            .expect("should get the half tree");
        assert_eq!(
            deposits.len(),
            4 as usize,
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
        let mut tree = DepositCache::default();

        for i in 0..n {
            let mut log = example_log();
            log.index = i;
            log.block_number = i;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i);
            tree.insert_log(log).expect("should add consecutive logs")
        }

        // Range too high.
        assert!(tree.get_deposits(0, n + 1, n, TREE_DEPTH).is_err());

        // Count too high.
        assert!(tree.get_deposits(0, n, n + 1, TREE_DEPTH).is_err());

        // Range higher than count.
        assert!(tree.get_deposits(0, 4, 2, TREE_DEPTH).is_err());
    }
}

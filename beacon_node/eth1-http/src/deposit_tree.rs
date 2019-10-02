use super::http::Log;
use eth2_hashing::hash;
use ssz::Decode;
use std::ops::Range;
use tree_hash::TreeHash;
use types::{Deposit, DepositData, Hash256, PublicKeyBytes, SignatureBytes};

#[derive(Debug, PartialEq)]
pub enum Error {
    NonConsecutive {
        log_index: u64,
        expected: usize,
    },
    LogParseError(String),
    InsufficientDeposits {
        known_deposits: usize,
        requested: u64,
    },
    DuplicateDistinctLog(u64),
    InternalError(String),
    DepositCountInvalid {
        deposit_count: u64,
        range_end: u64,
    },
}

/// The following constants define the layout of bytes in the deposit contract `DepositEvent`. The
/// event bytes are formatted according to the  Ethereum ABI.
const PUBKEY_START: usize = 192;
const PUBKEY_LEN: usize = 48;
const CREDS_START: usize = PUBKEY_START + 64 + 32;
const CREDS_LEN: usize = 32;
const AMOUNT_START: usize = CREDS_START + 32 + 32;
const AMOUNT_LEN: usize = 8;
const SIG_START: usize = AMOUNT_START + 32 + 32;
const SIG_LEN: usize = 96;
const INDEX_START: usize = SIG_START + 96 + 32;
const INDEX_LEN: usize = 8;

/// A fully parsed eth1 deposit contract log.
#[derive(Debug, PartialEq, Clone)]
pub struct DepositLog {
    pub deposit_data: DepositData,
    /// The block number of the log that included this `DepositData`.
    pub block_number: u64,
    /// The index included with the deposit log.
    pub index: u64,
}

impl DepositLog {
    /// Attempts to parse a raw `Log` from the deposit contract into a `DepositLog`.
    pub fn from_log(log: &Log) -> Result<Self, String> {
        let bytes = &log.data;

        let pubkey = bytes
            .get(PUBKEY_START..PUBKEY_START + PUBKEY_LEN)
            .ok_or_else(|| "Insufficient bytes for pubkey".to_string())?;
        let withdrawal_credentials = bytes
            .get(CREDS_START..CREDS_START + CREDS_LEN)
            .ok_or_else(|| "Insufficient bytes for withdrawal credential".to_string())?;
        let amount = bytes
            .get(AMOUNT_START..AMOUNT_START + AMOUNT_LEN)
            .ok_or_else(|| "Insufficient bytes for amount".to_string())?;
        let signature = bytes
            .get(SIG_START..SIG_START + SIG_LEN)
            .ok_or_else(|| "Insufficient bytes for signature".to_string())?;
        let index = bytes
            .get(INDEX_START..INDEX_START + INDEX_LEN)
            .ok_or_else(|| "Insufficient bytes for index".to_string())?;

        let deposit_data = DepositData {
            pubkey: PublicKeyBytes::from_ssz_bytes(pubkey)
                .map_err(|e| format!("Invalid index ssz: {:?}", e))?,
            withdrawal_credentials: Hash256::from_ssz_bytes(withdrawal_credentials)
                .map_err(|e| format!("Invalid withdrawal_credentials ssz: {:?}", e))?,
            amount: u64::from_ssz_bytes(amount)
                .map_err(|e| format!("Invalid amount ssz: {:?}", e))?,
            signature: SignatureBytes::from_ssz_bytes(signature)
                .map_err(|e| format!("Invalid signature ssz: {:?}", e))?,
        };

        Ok(DepositLog {
            deposit_data,
            block_number: log.block_number,
            index: u64::from_ssz_bytes(index).map_err(|e| format!("Invalid index ssz: {:?}", e))?,
        })
    }
}

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

    fn length_bytes(&self) -> Vec<u8> {
        int_to_bytes32(self.mix_in_length)
    }

    /// Retrieve the root hash of this Merkle tree.
    pub fn root(&self) -> Hash256 {
        let mut preimage = [0; 64];
        preimage[0..32].copy_from_slice(&self.tree.hash()[..]);
        preimage[32..64].copy_from_slice(&self.length_bytes());
        Hash256::from_slice(&hash(&preimage))
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(&self, index: usize) -> (Hash256, Vec<Hash256>) {
        let (root, mut proof) = self.tree.generate_proof(index, self.depth);
        proof.push(Hash256::from_slice(&self.length_bytes()));
        (root, proof)
    }
}

/// Mirrors the merkle tree of deposits in the eth1 deposit contract.
///
/// Provides `Deposit` objects will merkle proofs included.
pub struct DepositTree {
    logs: Vec<DepositLog>,
    roots: Vec<Hash256>,
}

impl DepositTree {
    /// Instantiate a new, empty tree.
    pub fn new() -> Self {
        Self {
            logs: vec![],
            roots: vec![],
        }
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
    /// - If `deposit_count` is larger than `range.end`.
    /// - There are not sufficient deposits in the tree to generate the proof.
    pub fn get_deposits(
        &self,
        range: Range<u64>,
        deposit_count: u64,
        tree_depth: usize,
    ) -> Result<(Hash256, Vec<Deposit>), Error> {
        if deposit_count < range.end {
            // It's invalid to ask for more deposits than should exist.
            Err(Error::DepositCountInvalid {
                deposit_count,
                range_end: range.end,
            })
        } else if range.end > self.logs.len() as u64 {
            // The range of requested deposits exceeds the deposits stored locally.
            Err(Error::InsufficientDeposits {
                requested: range.end,
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

            let tree = DepositDataTree::create(roots, deposit_count as usize, tree_depth);

            let deposits = self
                .logs
                .get(range.start as usize..range.end as usize)
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
mod tests {
    use super::*;

    const TREE_DEPTH: usize = 32;

    /// The data from a deposit event, using the v0.8.3 version of the deposit contract.
    const EXAMPLE_LOG: &[u8] = &[
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
        let log = Log {
            block_number: 42,
            data: EXAMPLE_LOG.to_vec(),
        };
        DepositLog::from_log(&log).expect("should decode log")
    }

    #[test]
    fn can_parse_log() {
        example_log();
    }

    #[test]
    fn insert_log_valid() {
        let mut tree = DepositTree::new();

        for i in 0..16 {
            let mut log = example_log();
            log.index = i;
            tree.insert_log(log).expect("should add consecutive logs")
        }
    }

    #[test]
    fn insert_log_invalid() {
        let mut tree = DepositTree::new();

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
        let mut tree = DepositTree::new();

        for i in 0..n {
            let mut log = example_log();
            log.index = i;
            log.block_number = i;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i);
            tree.insert_log(log).expect("should add consecutive logs")
        }

        // Get 0 deposits, with max deposit count.
        let (_, deposits) = tree
            .get_deposits(0..0, n, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get 0 deposits, with 0 deposit count.
        let (_, deposits) = tree
            .get_deposits(0..0, 0, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get 0 deposits, with 0 deposit count, tree depth 0.
        let (_, deposits) = tree
            .get_deposits(0..0, 0, 0)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), 0, "should return no deposits");

        // Get all deposits, with max deposit count.
        let (full_root, deposits) = tree
            .get_deposits(0..n, n, TREE_DEPTH)
            .expect("should get the full tree");
        assert_eq!(deposits.len(), n as usize, "should return all deposits");

        // Get 4 deposits, with max deposit count.
        let (root, deposits) = tree
            .get_deposits(0..4, n, TREE_DEPTH)
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
        let (half_root, deposits) = tree
            .get_deposits(0..n / 2, n / 2, TREE_DEPTH)
            .expect("should get the half tree");
        assert_eq!(
            deposits.len(),
            n as usize / 2,
            "should return half deposits"
        );

        // Get 4 deposits, with half deposit count.
        let (root, deposits) = tree
            .get_deposits(0..4, n / 2, TREE_DEPTH)
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
        let mut tree = DepositTree::new();

        for i in 0..n {
            let mut log = example_log();
            log.index = i;
            log.block_number = i;
            log.deposit_data.withdrawal_credentials = Hash256::from_low_u64_be(i);
            tree.insert_log(log).expect("should add consecutive logs")
        }

        // Range too high.
        assert!(tree.get_deposits(0..n + 1, n, TREE_DEPTH).is_err());

        // Count too high.
        assert!(tree.get_deposits(0..n, n + 1, TREE_DEPTH).is_err());

        // Range higher than count.
        assert!(tree.get_deposits(0..4, 2, TREE_DEPTH).is_err());
    }
}

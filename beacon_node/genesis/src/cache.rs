use crate::http::{Block as HttpBlock, Log};
use eth2_hashing::hash;
use ssz::Decode;
use state_processing::per_block_processing::verify_deposit_signature;
use std::ops::RangeInclusive;
use tree_hash::TreeHash;
use types::{ChainSpec, Deposit, DepositData, Hash256, PublicKeyBytes, SignatureBytes};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The timestamp of each block **must** be higher than the block prior to it.
    InconsistentTimestamp { parent: u64, child: u64 },
    /// There is no block prior to the given `target_secs`, unable to complete request.
    NoBlockForTarget {
        target_secs: u64,
        known_blocks: usize,
    },
    /// Some `Eth1Snapshot` was provided with the same block number but different data. The source
    /// of eth1 data is inconsistent.
    Conflicting(u64),
    /// The given snapshot was not one block number higher than the higest known block number.
    NonConsecutive { given: u64, expected: u64 },
    /// The given block number is too large to fit in a usize.
    BlockNumberTooLarge(u64),
    /// Failed to decode a log. This is unexpected, _all_ logs should be decodable.
    DepositLogParseFailed(String),
    /// Some invariant was violated, there is a likely bug in the code.
    Internal(String),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub hash: Hash256,
    pub timestamp: u64,
    pub number: u64,
    pub deposit_root: Hash256,
    pub deposit_count: u64,
    pub deposit_logs: Vec<DepositLog>,
}

#[derive(Default)]
pub struct BlockCache {
    blocks: Vec<Block>,
}

impl BlockCache {
    /// Returns the highest block number stored.
    pub fn highest_block_number(&self) -> Option<u64> {
        self.blocks.last().map(|block| block.number)
    }

    /// Returns an iterator over all blocks.
    ///
    /// Blocks will be returned with:
    ///
    /// - Monotically increase block numbers.
    /// - Non-uniformly increasing block timestamps.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.iter()
    }

    /// Returns the range of block numbers stored in the block cache. All blocks in this range can
    /// be accessed.
    fn available_block_numbers(&self) -> Option<RangeInclusive<u64>> {
        Some(self.blocks.first()?.number..=self.blocks.last()?.number)
    }

    /// Returns a block with the corresponding number, if any.
    fn block_by_number(&self, target: u64) -> Option<&Block> {
        self.blocks.get(self.block_index_by_block_number(target)?)
    }

    /// Returns a block with the corresponding number, if any.
    fn block_index_by_block_number(&self, target: u64) -> Option<usize> {
        self.blocks
            .as_slice()
            .binary_search_by(|block| block.number.cmp(&target))
            .ok()
    }

    /// Insert an `Eth1Snapshot` into `self`, allowing future queries.
    ///
    /// ## Errors
    ///
    /// - If `item.block.block_number - 1` is not already in `self`.
    /// - If `item.block.block_number` is in `self`, but is not identical to the supplied
    /// `Eth1Snapshot`.
    /// - If `item.block.timestamp` is prior to the parent.
    pub fn insert_child(
        &mut self,
        http_block: HttpBlock,
        deposit_root: Hash256,
        deposit_count: u64,
        logs: &[Log],
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let block = Block {
            hash: http_block.hash,
            timestamp: http_block.timestamp,
            number: http_block.number,
            deposit_root,
            deposit_count,
            deposit_logs: logs
                .iter()
                .map(|log| DepositLog::from_log(log, spec))
                .collect::<Result<_, _>>()
                .map_err(|e| Error::DepositLogParseFailed(e))?,
        };

        let expected_block_number = self
            .highest_block_number()
            .map(|n| n + 1)
            .unwrap_or_else(|| block.number);

        // Only permit blocks when it's either:
        //
        // - The first block inserted.
        // - Exactly only block number higher than the highest known block number.
        if block.number != expected_block_number {
            return Err(Error::NonConsecutive {
                given: block.number,
                expected: expected_block_number,
            });
        }

        // If there are already some cached blocks, check to see if the new block number is one of
        // them.
        //
        // If the block is already known, check to see the given block is identical to it. If not,
        // raise an inconsistency error. This is mostly likely caused by some fork on the eth1
        // chain.
        if let Some(local) = self.available_block_numbers() {
            if local.contains(&block.number) {
                let known_block = self.block_by_number(block.number).ok_or_else(|| {
                    Error::Internal("An expected block was not present".to_string())
                })?;

                if known_block == &block {
                    return Ok(());
                } else {
                    return Err(Error::Conflicting(block.number));
                };
            }
        }

        // If the block is not the first block inserted, ensure that it's timestamp is not higher
        // than it's parents.
        if let Some(previous_block) = self.blocks.last() {
            if previous_block.timestamp > block.timestamp {
                return Err(Error::InconsistentTimestamp {
                    parent: previous_block.timestamp,
                    child: block.timestamp,
                });
            }
        }

        self.blocks.push(block);

        Ok(())
    }
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

/// Represents an eth1 deposit contract merkle tree.
///
/// Each `deposit` is included with a proof into the `deposit_root`. The index for a deposit in the
/// merkle tree is equal to it's index in `deposits`.
pub struct DepositSet {
    pub deposit_root: Hash256,
    pub deposits: Vec<Deposit>,
}

impl DepositSet {
    pub fn from_logs(tree_depth: usize, logs: Vec<DepositLog>) -> Self {
        let roots = logs
            .iter()
            .map(|log| Hash256::from_slice(&log.deposit_data.tree_hash_root()))
            .collect::<Vec<_>>();

        let tree = DepositDataTree::create(&roots, roots.len(), tree_depth);

        let deposits = logs
            .into_iter()
            .enumerate()
            .map(|(i, deposit_log)| {
                let (_leaf, proof) = tree.generate_proof(i);

                Deposit {
                    proof: proof.into(),
                    data: deposit_log.deposit_data,
                }
            })
            .collect();

        DepositSet {
            deposit_root: tree.root(),
            deposits,
        }
    }

    pub fn into_components(self) -> (Hash256, Vec<Deposit>) {
        (self.deposit_root, self.deposits)
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: usize) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}

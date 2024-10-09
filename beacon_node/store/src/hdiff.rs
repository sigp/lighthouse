//! Hierarchical diff implementation.
use crate::{metrics, DBColumn, StoreConfig, StoreItem};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::{Read, Write};
use std::str::FromStr;
use types::{BeaconState, ChainSpec, EthSpec, List, Slot};
use zstd::{Decoder, Encoder};

#[derive(Debug)]
pub enum Error {
    InvalidHierarchy,
    U64DiffDeletionsNotSupported,
    UnableToComputeDiff,
    UnableToApplyDiff,
    BalancesIncompleteChunk,
    Compression(std::io::Error),
    InvalidSszState(ssz::DecodeError),
    InvalidBalancesLength,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct HierarchyConfig {
    /// A sequence of powers of two to define how frequently to store each layer of state diffs.
    /// The last value always represents the frequency of full state snapshots. Adding more
    /// exponents increases the number of diff layers. This value allows to customize the trade-off
    /// between reconstruction speed and disk space.
    ///
    /// Consider an example `exponents value of `[5,13,21]`. This means we have 3 layers:
    /// - Full state stored every 2^21 slots (2097152 slots or 291 days)
    /// - First diff layer stored every 2^13 slots (8192 slots or 2.3 hours)
    /// - Second diff layer stored every 2^5 slots (32 slots or 1 epoch)
    ///
    /// To reconstruct a state at slot 3,000,003 we load each closest layer
    /// - Layer 0: 3000003 - (3000003 mod 2^21) = 2097152
    /// - Layer 1: 3000003 - (3000003 mod 2^13) = 2998272
    /// - Layer 2: 3000003 - (3000003 mod 2^5)  = 3000000
    ///
    /// Layer 0 is full state snaphost, apply layer 1 diff, then apply layer 2 diff and then replay
    /// blocks 3,000,001 to 3,000,003.
    pub exponents: Vec<u8>,
}

impl FromStr for HierarchyConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let exponents = s
            .split(',')
            .map(|s| {
                s.parse()
                    .map_err(|e| format!("invalid hierarchy-exponents: {e:?}"))
            })
            .collect::<Result<Vec<u8>, _>>()?;

        if exponents.windows(2).any(|w| w[0] >= w[1]) {
            return Err("hierarchy-exponents must be in ascending order".to_string());
        }

        Ok(HierarchyConfig { exponents })
    }
}

#[derive(Debug)]
pub struct HierarchyModuli {
    moduli: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StorageStrategy {
    ReplayFrom(Slot),
    DiffFrom(Slot),
    Snapshot,
}

/// Hierarchical diff output and working buffer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HDiffBuffer {
    pub state: Vec<u8>,
    pub balances: Vec<u64>,
}

/// Hierarchical state diff.
///
/// Splits the diff into two data sections:
///
/// - **balances**: The balance of each active validator is almost certain to change every epoch.
///   So this is the field in the state with most entropy. However the balance changes are small.
///   We can optimize the diff significantly by computing the balance difference first and then
///   compressing the result to squash those leading zero bytes.
///
/// - **everything else**: Instead of trying to apply heuristics and be clever on each field,
///   running a generic binary diff algorithm on the rest of fields yields very good results. With
///   this strategy the HDiff code is easily mantainable across forks, as new fields are covered
///   automatically. xdelta3 algorithm showed diff compute and apply times of ~200 ms on a mainnet
///   state from Apr 2023 (570k indexes), and a 92kB diff size.
#[derive(Debug, Encode, Decode)]
pub struct HDiff {
    state_diff: BytesDiff,
    balances_diff: CompressedU64Diff,
}

#[derive(Debug, Encode, Decode)]
pub struct BytesDiff {
    bytes: Vec<u8>,
}

#[derive(Debug, Encode, Decode)]
pub struct CompressedU64Diff {
    bytes: Vec<u8>,
}

impl HDiffBuffer {
    pub fn from_state<E: EthSpec>(mut beacon_state: BeaconState<E>) -> Self {
        let _t = metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_FROM_STATE_TIME);
        // Set state.balances to empty list, and then serialize state as ssz
        let balances_list = std::mem::take(beacon_state.balances_mut());

        let state = beacon_state.as_ssz_bytes();
        let balances = balances_list.to_vec();

        HDiffBuffer { state, balances }
    }

    pub fn as_state<E: EthSpec>(&self, spec: &ChainSpec) -> Result<BeaconState<E>, Error> {
        let _t = metrics::start_timer(&metrics::STORE_BEACON_HDIFF_BUFFER_INTO_STATE_TIME);
        let mut state =
            BeaconState::from_ssz_bytes(&self.state, spec).map_err(Error::InvalidSszState)?;
        *state.balances_mut() = List::try_from_iter(self.balances.iter().copied())
            .map_err(|_| Error::InvalidBalancesLength)?;
        Ok(state)
    }

    /// Byte size of this instance
    pub fn size(&self) -> usize {
        self.state.len() + self.balances.len() * std::mem::size_of::<u64>()
    }
}

impl HDiff {
    pub fn compute(
        source: &HDiffBuffer,
        target: &HDiffBuffer,
        config: &StoreConfig,
    ) -> Result<Self, Error> {
        let state_diff = BytesDiff::compute(&source.state, &target.state)?;
        let balances_diff = CompressedU64Diff::compute(&source.balances, &target.balances, config)?;

        Ok(Self {
            state_diff,
            balances_diff,
        })
    }

    pub fn apply(&self, source: &mut HDiffBuffer, config: &StoreConfig) -> Result<(), Error> {
        let source_state = std::mem::take(&mut source.state);
        self.state_diff.apply(&source_state, &mut source.state)?;

        self.balances_diff.apply(&mut source.balances, config)?;
        Ok(())
    }

    pub fn state_diff_len(&self) -> usize {
        self.state_diff.bytes.len()
    }

    pub fn balances_diff_len(&self) -> usize {
        self.balances_diff.bytes.len()
    }
}

impl StoreItem for HDiff {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateDiff
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

impl BytesDiff {
    pub fn compute(source: &[u8], target: &[u8]) -> Result<Self, Error> {
        Self::compute_xdelta(source, target)
    }

    pub fn compute_xdelta(source_bytes: &[u8], target_bytes: &[u8]) -> Result<Self, Error> {
        let bytes =
            xdelta3::encode(target_bytes, source_bytes).ok_or(Error::UnableToComputeDiff)?;
        Ok(Self { bytes })
    }

    pub fn apply(&self, source: &[u8], target: &mut Vec<u8>) -> Result<(), Error> {
        self.apply_xdelta(source, target)
    }

    pub fn apply_xdelta(&self, source: &[u8], target: &mut Vec<u8>) -> Result<(), Error> {
        *target = xdelta3::decode(&self.bytes, source).ok_or(Error::UnableToApplyDiff)?;
        Ok(())
    }
}

impl CompressedU64Diff {
    pub fn compute(xs: &[u64], ys: &[u64], config: &StoreConfig) -> Result<Self, Error> {
        if xs.len() > ys.len() {
            return Err(Error::U64DiffDeletionsNotSupported);
        }

        let uncompressed_bytes: Vec<u8> = ys
            .iter()
            .enumerate()
            .flat_map(|(i, y)| {
                // Diff from 0 if the entry is new.
                let x = xs.get(i).copied().unwrap_or(0);
                y.wrapping_sub(x).to_be_bytes()
            })
            .collect();

        let compression_level = config.compression_level;
        let mut compressed_bytes =
            Vec::with_capacity(config.estimate_compressed_size(uncompressed_bytes.len()));
        let mut encoder =
            Encoder::new(&mut compressed_bytes, compression_level).map_err(Error::Compression)?;
        encoder
            .write_all(&uncompressed_bytes)
            .map_err(Error::Compression)?;
        encoder.finish().map_err(Error::Compression)?;

        Ok(CompressedU64Diff {
            bytes: compressed_bytes,
        })
    }

    pub fn apply(&self, xs: &mut Vec<u64>, config: &StoreConfig) -> Result<(), Error> {
        // Decompress balances diff.
        let mut balances_diff_bytes =
            Vec::with_capacity(config.estimate_decompressed_size(self.bytes.len()));
        let mut decoder = Decoder::new(&*self.bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut balances_diff_bytes)
            .map_err(Error::Compression)?;

        for (i, diff_bytes) in balances_diff_bytes
            .chunks(u64::BITS as usize / 8)
            .enumerate()
        {
            let diff = diff_bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::BalancesIncompleteChunk)?;

            if let Some(x) = xs.get_mut(i) {
                *x = x.wrapping_add(diff);
            } else {
                xs.push(diff);
            }
        }

        Ok(())
    }
}

impl Default for HierarchyConfig {
    fn default() -> Self {
        HierarchyConfig {
            exponents: vec![5, 9, 11, 13, 16, 18, 21],
        }
    }
}

impl HierarchyConfig {
    pub fn to_moduli(&self) -> Result<HierarchyModuli, Error> {
        self.validate()?;
        let moduli = self.exponents.iter().map(|n| 1 << n).collect();
        Ok(HierarchyModuli { moduli })
    }

    pub fn validate(&self) -> Result<(), Error> {
        if !self.exponents.is_empty()
            && self
                .exponents
                .iter()
                .tuple_windows()
                .all(|(small, big)| small < big && *big < u64::BITS as u8)
        {
            Ok(())
        } else {
            Err(Error::InvalidHierarchy)
        }
    }
}

impl HierarchyModuli {
    pub fn storage_strategy(&self, slot: Slot) -> Result<StorageStrategy, Error> {
        // last = full snapshot interval
        let last = self.moduli.last().copied().ok_or(Error::InvalidHierarchy)?;
        // first = most frequent diff layer, need to replay blocks from this layer
        let first = self
            .moduli
            .first()
            .copied()
            .ok_or(Error::InvalidHierarchy)?;

        if slot % last == 0 {
            return Ok(StorageStrategy::Snapshot);
        }

        Ok(self
            .moduli
            .iter()
            .rev()
            .tuple_windows()
            .find_map(|(&n_big, &n_small)| {
                if slot % n_small == 0 {
                    // Diff from the previous layer.
                    Some(StorageStrategy::DiffFrom(slot / n_big * n_big))
                } else {
                    // Keep trying with next layer
                    None
                }
            })
            // Exhausted layers, need to replay from most frequent layer
            .unwrap_or(StorageStrategy::ReplayFrom(slot / first * first)))
    }

    /// Return the smallest slot greater than or equal to `slot` at which a full snapshot should
    /// be stored.
    pub fn next_snapshot_slot(&self, slot: Slot) -> Result<Slot, Error> {
        let last = self.moduli.last().copied().ok_or(Error::InvalidHierarchy)?;
        if slot % last == 0 {
            Ok(slot)
        } else {
            Ok((slot / last + 1) * last)
        }
    }

    /// Return `true` if the database ops for this slot should be committed immediately.
    ///
    /// This is the case for all diffs aside from the ones in the leaf layer. To store a diff
    /// might require loading the state at the previous layer, in which case the diff for that
    /// layer must already have been stored.
    ///
    /// In future we may be able to handle this differently (with proper transaction semantics
    /// rather than LevelDB's "write batches").
    pub fn should_commit_immediately(&self, slot: Slot) -> Result<bool, Error> {
        // If there's only 1 layer of snapshots, then commit only when writing a snapshot.
        self.moduli.get(1).map_or_else(
            || Ok(slot == self.next_snapshot_slot(slot)?),
            |second_layer_moduli| Ok(slot % *second_layer_moduli == 0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_storage_strategy() {
        let config = HierarchyConfig::default();
        config.validate().unwrap();

        let moduli = config.to_moduli().unwrap();

        // Full snapshots at multiples of 2^21.
        let snapshot_freq = Slot::new(1 << 21);
        assert_eq!(
            moduli.storage_strategy(Slot::new(0)).unwrap(),
            StorageStrategy::Snapshot
        );
        assert_eq!(
            moduli.storage_strategy(snapshot_freq).unwrap(),
            StorageStrategy::Snapshot
        );
        assert_eq!(
            moduli.storage_strategy(snapshot_freq * 3).unwrap(),
            StorageStrategy::Snapshot
        );

        // Diffs should be from the previous layer (the snapshot in this case), and not the previous diff in the same layer.
        let first_layer = Slot::new(1 << 18);
        assert_eq!(
            moduli.storage_strategy(first_layer * 2).unwrap(),
            StorageStrategy::DiffFrom(Slot::new(0))
        );

        let replay_strategy_slot = first_layer + 1;
        assert_eq!(
            moduli.storage_strategy(replay_strategy_slot).unwrap(),
            StorageStrategy::ReplayFrom(first_layer)
        );
    }

    #[test]
    fn next_snapshot_slot() {
        let config = HierarchyConfig::default();
        config.validate().unwrap();

        let moduli = config.to_moduli().unwrap();
        let snapshot_freq = Slot::new(1 << 21);

        assert_eq!(
            moduli.next_snapshot_slot(snapshot_freq).unwrap(),
            snapshot_freq
        );
        assert_eq!(
            moduli.next_snapshot_slot(snapshot_freq + 1).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_slot(snapshot_freq * 2 - 1).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_slot(snapshot_freq * 2).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_slot(snapshot_freq * 100).unwrap(),
            snapshot_freq * 100
        );
    }

    #[test]
    fn compressed_u64_vs_bytes_diff() {
        let x_values = vec![99u64, 55, 123, 6834857, 0, 12];
        let y_values = vec![98u64, 55, 312, 1, 1, 2, 4, 5];
        let config = &StoreConfig::default();

        let to_bytes =
            |nums: &[u64]| -> Vec<u8> { nums.iter().flat_map(|x| x.to_be_bytes()).collect() };

        let x_bytes = to_bytes(&x_values);
        let y_bytes = to_bytes(&y_values);

        let u64_diff = CompressedU64Diff::compute(&x_values, &y_values, config).unwrap();

        let mut y_from_u64_diff = x_values;
        u64_diff.apply(&mut y_from_u64_diff, config).unwrap();

        assert_eq!(y_values, y_from_u64_diff);

        let bytes_diff = BytesDiff::compute(&x_bytes, &y_bytes).unwrap();

        let mut y_from_bytes = vec![];
        bytes_diff.apply(&x_bytes, &mut y_from_bytes).unwrap();

        assert_eq!(y_bytes, y_from_bytes);

        // U64 diff wins by more than a factor of 3
        assert!(u64_diff.bytes.len() < 3 * bytes_diff.bytes.len());
    }
}

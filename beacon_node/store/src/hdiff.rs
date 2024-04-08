//! Hierarchical diff implementation.
use crate::{DBColumn, StoreItem};
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
    Compression(std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct HierarchyConfig {
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
    state: Vec<u8>,
    balances: Vec<u64>,
}

/// Hierarchical state diff.
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
        let balances_list = std::mem::take(beacon_state.balances_mut());

        let state = beacon_state.as_ssz_bytes();
        let balances = balances_list.to_vec();

        HDiffBuffer { state, balances }
    }

    pub fn into_state<E: EthSpec>(self, spec: &ChainSpec) -> Result<BeaconState<E>, Error> {
        let mut state = BeaconState::from_ssz_bytes(&self.state, spec).unwrap();
        *state.balances_mut() = List::new(self.balances).unwrap();
        Ok(state)
    }
}

impl HDiff {
    pub fn compute(source: &HDiffBuffer, target: &HDiffBuffer) -> Result<Self, Error> {
        let state_diff = BytesDiff::compute(&source.state, &target.state)?;
        let balances_diff = CompressedU64Diff::compute(&source.balances, &target.balances)?;

        Ok(Self {
            state_diff,
            balances_diff,
        })
    }

    pub fn apply(&self, source: &mut HDiffBuffer) -> Result<(), Error> {
        let source_state = std::mem::take(&mut source.state);
        self.state_diff.apply(&source_state, &mut source.state)?;

        self.balances_diff.apply(&mut source.balances)?;
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
    pub fn compute(xs: &[u64], ys: &[u64]) -> Result<Self, Error> {
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

        // FIXME(sproul): reconsider
        let compression_level = 1;
        let mut compressed_bytes = Vec::with_capacity(uncompressed_bytes.len() / 2);
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

    pub fn apply(&self, xs: &mut Vec<u64>) -> Result<(), Error> {
        // Decompress balances diff.
        let mut balances_diff_bytes = Vec::with_capacity(2 * self.bytes.len());
        let mut decoder = Decoder::new(&*self.bytes).map_err(Error::Compression)?;
        decoder
            .read_to_end(&mut balances_diff_bytes)
            .map_err(Error::Compression)?;

        for (i, diff_bytes) in balances_diff_bytes
            .chunks(u64::BITS as usize / 8)
            .enumerate()
        {
            // FIXME(sproul): unwrap
            let diff = u64::from_be_bytes(diff_bytes.try_into().unwrap());

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
        if self.exponents.len() > 2
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
        let last = self.moduli.last().copied().ok_or(Error::InvalidHierarchy)?;
        let first = self
            .moduli
            .first()
            .copied()
            .ok_or(Error::InvalidHierarchy)?;
        let replay_from = slot / first * first;

        if slot % last == 0 {
            return Ok(StorageStrategy::Snapshot);
        }

        let diff_from = self
            .moduli
            .iter()
            .rev()
            .tuple_windows()
            .find_map(|(&n_big, &n_small)| {
                (slot % n_small == 0).then(|| {
                    // Diff from the previous layer.
                    slot / n_big * n_big
                })
            });

        Ok(diff_from.map_or(
            StorageStrategy::ReplayFrom(replay_from),
            StorageStrategy::DiffFrom,
        ))
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
    /// This is the case for all diffs in the 2nd lowest layer and above, which are required by diffs
    /// in the 1st layer.
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

        let to_bytes =
            |nums: &[u64]| -> Vec<u8> { nums.iter().flat_map(|x| x.to_be_bytes()).collect() };

        let x_bytes = to_bytes(&x_values);
        let y_bytes = to_bytes(&y_values);

        let u64_diff = CompressedU64Diff::compute(&x_values, &y_values).unwrap();

        let mut y_from_u64_diff = x_values;
        u64_diff.apply(&mut y_from_u64_diff).unwrap();

        assert_eq!(y_values, y_from_u64_diff);

        let bytes_diff = BytesDiff::compute(&x_bytes, &y_bytes).unwrap();

        let mut y_from_bytes = vec![];
        bytes_diff.apply(&x_bytes, &mut y_from_bytes).unwrap();

        assert_eq!(y_bytes, y_from_bytes);

        // U64 diff wins by more than a factor of 3
        assert!(u64_diff.bytes.len() < 3 * bytes_diff.bytes.len());
    }
}

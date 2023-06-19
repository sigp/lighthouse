//! Hierarchical diff implementation.
use crate::{DBColumn, StoreItem};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::{Read, Write};
use types::{BeaconState, ChainSpec, Epoch, EthSpec, VList};
use zstd::{Decoder, Encoder};

#[derive(Debug)]
pub enum Error {
    InvalidHierarchy,
    XorDeletionsNotSupported,
    UnableToComputeDiff,
    UnableToApplyDiff,
    Compression(std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HierarchyConfig {
    exponents: Vec<u8>,
}

#[derive(Debug)]
pub struct HierarchyModuli {
    moduli: Vec<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StorageStrategy {
    Nothing,
    DiffFrom(Epoch),
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
    balances_diff: XorDiff,
}

#[derive(Debug, Encode, Decode)]
pub struct BytesDiff {
    bytes: Vec<u8>,
}

#[derive(Debug, Encode, Decode)]
pub struct XorDiff {
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
        *state.balances_mut() = VList::new(self.balances).unwrap();
        Ok(state)
    }
}

impl HDiff {
    pub fn compute(source: &HDiffBuffer, target: &HDiffBuffer) -> Result<Self, Error> {
        let state_diff = BytesDiff::compute(&source.state, &target.state)?;
        let balances_diff = XorDiff::compute(&source.balances, &target.balances)?;

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

    fn as_store_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        Ok(self.as_ssz_bytes())
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

impl XorDiff {
    pub fn compute(xs: &[u64], ys: &[u64]) -> Result<Self, Error> {
        if xs.len() > ys.len() {
            return Err(Error::XorDeletionsNotSupported);
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

        Ok(XorDiff {
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
            exponents: vec![0, 4, 6, 8, 11, 13, 16],
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
    pub fn storage_strategy(&self, epoch: Epoch) -> Result<StorageStrategy, Error> {
        let last = self.moduli.last().copied().ok_or(Error::InvalidHierarchy)?;

        if epoch % last == 0 {
            return Ok(StorageStrategy::Snapshot);
        }

        let diff_from = self.moduli.iter().rev().find_map(|&n| {
            (epoch % n == 0).then(|| {
                // Diff from the previous state.
                (epoch - 1) / n * n
            })
        });
        Ok(diff_from.map_or(StorageStrategy::Nothing, StorageStrategy::DiffFrom))
    }

    /// Return the smallest epoch greater than or equal to `epoch` at which a full snapshot should
    /// be stored.
    pub fn next_snapshot_epoch(&self, epoch: Epoch) -> Result<Epoch, Error> {
        let last = self.moduli.last().copied().ok_or(Error::InvalidHierarchy)?;
        if epoch % last == 0 {
            Ok(epoch)
        } else {
            Ok((epoch / last + 1) * last)
        }
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

        // Full snapshots at multiples of 2^16.
        let snapshot_freq = Epoch::new(1 << 16);
        assert_eq!(
            moduli.storage_strategy(Epoch::new(0)).unwrap(),
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

        // For the first layer of diffs
        let first_layer = Epoch::new(1 << 13);
        assert_eq!(
            moduli.storage_strategy(first_layer * 2).unwrap(),
            StorageStrategy::DiffFrom(first_layer)
        );
    }

    #[test]
    fn next_snapshot_epoch() {
        let config = HierarchyConfig::default();
        config.validate().unwrap();

        let moduli = config.to_moduli().unwrap();
        let snapshot_freq = Epoch::new(1 << 16);

        assert_eq!(
            moduli.next_snapshot_epoch(snapshot_freq).unwrap(),
            snapshot_freq
        );
        assert_eq!(
            moduli.next_snapshot_epoch(snapshot_freq + 1).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_epoch(snapshot_freq * 2 - 1).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_epoch(snapshot_freq * 2).unwrap(),
            snapshot_freq * 2
        );
        assert_eq!(
            moduli.next_snapshot_epoch(snapshot_freq * 100).unwrap(),
            snapshot_freq * 100
        );
    }

    #[test]
    fn xor_vs_bytes_diff() {
        let x_values = vec![99u64, 55, 123, 6834857, 0, 12];
        let y_values = vec![98u64, 55, 312, 1, 1, 2, 4, 5];

        let to_bytes =
            |nums: &[u64]| -> Vec<u8> { nums.iter().flat_map(|x| x.to_be_bytes()).collect() };

        let x_bytes = to_bytes(&x_values);
        let y_bytes = to_bytes(&y_values);

        let xor_diff = XorDiff::compute(&x_values, &y_values).unwrap();

        let mut y_from_xor = x_values;
        xor_diff.apply(&mut y_from_xor).unwrap();

        assert_eq!(y_values, y_from_xor);

        let bytes_diff = BytesDiff::compute(&x_bytes, &y_bytes).unwrap();

        let mut y_from_bytes = vec![];
        bytes_diff.apply(&x_bytes, &mut y_from_bytes).unwrap();

        assert_eq!(y_bytes, y_from_bytes);

        // XOR diff wins by more than a factor of 3
        assert!(xor_diff.bytes.len() < 3 * bytes_diff.bytes.len());
    }
}

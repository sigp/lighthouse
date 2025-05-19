use crate::{ChainSpec, ColumnIndex, DataColumnSubnetId};
use alloy_primitives::U256;
use itertools::Itertools;
use maplit::hashset;
use safe_arith::{ArithError, SafeArith};
use std::collections::HashSet;

pub type CustodyIndex = u64;

#[derive(Debug)]
pub enum DataColumnCustodyGroupError {
    InvalidCustodyGroup(CustodyIndex),
    InvalidCustodyGroupCount(u64),
    ArithError(ArithError),
}

/// The `get_custody_groups` function is used to determine the custody groups that a node is
/// assigned to.
///
/// Note: `get_custody_groups(node_id, x)` is a subset of `get_custody_groups(node_id, y)` if `x < y`.
///
/// spec: https://github.com/ethereum/consensus-specs/blob/8e0d0d48e81d6c7c5a8253ab61340f5ea5bac66a/specs/fulu/das-core.md#get_custody_groups
pub fn get_custody_groups(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    spec: &ChainSpec,
) -> Result<HashSet<CustodyIndex>, DataColumnCustodyGroupError> {
    if custody_group_count > spec.number_of_custody_groups {
        return Err(DataColumnCustodyGroupError::InvalidCustodyGroupCount(
            custody_group_count,
        ));
    }

    let mut custody_groups: HashSet<u64> = hashset![];
    let mut current_id = U256::from_be_slice(&raw_node_id);
    while custody_groups.len() < custody_group_count as usize {
        let mut node_id_bytes = [0u8; 32];
        node_id_bytes.copy_from_slice(current_id.as_le_slice());
        let hash = ethereum_hashing::hash_fixed(&node_id_bytes);
        let hash_prefix: [u8; 8] = hash[0..8]
            .try_into()
            .expect("hash_fixed produces a 32 byte array");
        let hash_prefix_u64 = u64::from_le_bytes(hash_prefix);
        let custody_group = hash_prefix_u64
            .safe_rem(spec.number_of_custody_groups)
            .expect("spec.number_of_custody_groups must not be zero");
        custody_groups.insert(custody_group);

        current_id = current_id.wrapping_add(U256::from(1u64));
    }

    Ok(custody_groups)
}

/// Returns the columns that are associated with a given custody group.
///
/// spec: https://github.com/ethereum/consensus-specs/blob/8e0d0d48e81d6c7c5a8253ab61340f5ea5bac66a/specs/fulu/das-core.md#compute_columns_for_custody_group
pub fn compute_columns_for_custody_group(
    custody_group: CustodyIndex,
    spec: &ChainSpec,
) -> Result<impl Iterator<Item = ColumnIndex>, DataColumnCustodyGroupError> {
    let number_of_custody_groups = spec.number_of_custody_groups;
    if custody_group >= number_of_custody_groups {
        return Err(DataColumnCustodyGroupError::InvalidCustodyGroup(
            custody_group,
        ));
    }

    let mut columns = Vec::new();
    for i in 0..spec.data_columns_per_group() {
        let column = number_of_custody_groups
            .safe_mul(i)
            .and_then(|v| v.safe_add(custody_group))
            .map_err(DataColumnCustodyGroupError::ArithError)?;
        columns.push(column);
    }

    Ok(columns.into_iter())
}

pub fn compute_subnets_for_node(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    spec: &ChainSpec,
) -> Result<HashSet<DataColumnSubnetId>, DataColumnCustodyGroupError> {
    let custody_groups = get_custody_groups(raw_node_id, custody_group_count, spec)?;
    let mut subnets = HashSet::new();

    for custody_group in custody_groups {
        let custody_group_subnets = compute_subnets_from_custody_group(custody_group, spec)?;
        subnets.extend(custody_group_subnets);
    }

    Ok(subnets)
}

/// Returns the subnets that are associated with a given custody group.
pub fn compute_subnets_from_custody_group(
    custody_group: CustodyIndex,
    spec: &ChainSpec,
) -> Result<impl Iterator<Item = DataColumnSubnetId> + '_, DataColumnCustodyGroupError> {
    let result = compute_columns_for_custody_group(custody_group, spec)?
        .map(|column_index| DataColumnSubnetId::from_column_index(column_index, spec))
        .unique();
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compute_columns_for_custody_group() {
        let mut spec = ChainSpec::mainnet();
        spec.number_of_custody_groups = 64;
        spec.number_of_columns = 128;
        let columns_per_custody_group = spec.number_of_columns / spec.number_of_custody_groups;

        for custody_group in 0..spec.number_of_custody_groups {
            let columns = compute_columns_for_custody_group(custody_group, &spec)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(columns.len(), columns_per_custody_group as usize);
        }
    }

    #[test]
    fn test_compute_subnets_from_custody_group() {
        let mut spec = ChainSpec::mainnet();
        spec.number_of_custody_groups = 64;
        spec.number_of_columns = 256;
        spec.data_column_sidecar_subnet_count = 128;

        let subnets_per_custody_group =
            spec.data_column_sidecar_subnet_count / spec.number_of_custody_groups;

        for custody_group in 0..spec.number_of_custody_groups {
            let subnets = compute_subnets_from_custody_group(custody_group, &spec)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(subnets.len(), subnets_per_custody_group as usize);
        }
    }
}

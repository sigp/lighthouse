use crate::{ChainSpec, ColumnIndex, DataColumnSubnetId};
use alloy_primitives::U256;
use itertools::Itertools;
use maplit::hashset;
use std::collections::HashSet;

pub type CustodyIndex = u64;

/// The `get_custody_groups` function is used to determine the custody groups that a node is
/// assigned to.
///
/// spec: https://github.com/ethereum/consensus-specs/blob/8e0d0d48e81d6c7c5a8253ab61340f5ea5bac66a/specs/fulu/das-core.md#get_custody_groups
#[allow(clippy::arithmetic_side_effects)]
pub fn get_custody_groups(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    spec: &ChainSpec,
) -> HashSet<CustodyIndex> {
    // TODO: validate input
    // assert custody_group_count <= NUMBER_OF_CUSTODY_GROUPS
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
        let custody_group = hash_prefix_u64 % spec.number_of_custody_groups;
        custody_groups.insert(custody_group);

        if current_id == U256::MAX {
            current_id = U256::ZERO
        }
        current_id += U256::from(1u64)
    }

    // assert len(custody_groups) == len(set(custody_groups))
    custody_groups
}

/// Returns the columns that are associated with a given custody group.
///
/// spec: https://github.com/ethereum/consensus-specs/blob/8e0d0d48e81d6c7c5a8253ab61340f5ea5bac66a/specs/fulu/das-core.md#compute_columns_for_custody_group
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_columns_for_custody_group(
    custody_group: CustodyIndex,
    spec: &ChainSpec,
) -> impl Iterator<Item = ColumnIndex> {
    // TODO: this must be validated to avoid panics
    // assert custody_group < NUMBER_OF_CUSTODY_GROUPS
    let number_of_custody_groups = spec.number_of_custody_groups;
    (0..spec.data_columns_per_group()).map(move |i| number_of_custody_groups * i + custody_group)
}

pub fn compute_subnets_for_node(
    raw_node_id: [u8; 32],
    custody_group_count: u64,
    spec: &ChainSpec,
) -> impl Iterator<Item = DataColumnSubnetId> + '_ {
    get_custody_groups(raw_node_id, custody_group_count, spec)
        .into_iter()
        .flat_map(|custody_group| compute_subnets_from_custody_group(custody_group, spec))
}

/// Returns the subnets that are associated with a given custody group.
pub fn compute_subnets_from_custody_group(
    custody_group: CustodyIndex,
    spec: &ChainSpec,
) -> impl Iterator<Item = DataColumnSubnetId> + '_ {
    compute_columns_for_custody_group(custody_group, spec)
        .map(|column_index| DataColumnSubnetId::from_column_index(column_index, spec))
        .unique()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_compute_columns_for_custody_group() {
        let number_of_custody_groups = 64;
        let spec = ChainSpec {
            number_of_columns: 128,
            number_of_custody_groups,
            ..ChainSpec::mainnet()
        };
        let columns_per_custody_group = spec.number_of_columns / number_of_custody_groups;

        for custody_group in 0..number_of_custody_groups {
            let columns =
                compute_columns_for_custody_group(custody_group, &spec).collect::<Vec<_>>();
            assert_eq!(columns.len(), columns_per_custody_group as usize);
        }
    }

    #[test]
    fn test_compute_subnets_from_custody_group() {
        let spec = ChainSpec {
            number_of_columns: 256,
            number_of_custody_groups: 64,
            data_column_sidecar_subnet_count: 128,
            ..ChainSpec::mainnet()
        };
        let subnets_per_custody_group =
            spec.data_column_sidecar_subnet_count / spec.number_of_custody_groups;

        for custody_group in 0..spec.number_of_custody_groups {
            let subnets =
                compute_subnets_from_custody_group(custody_group, &spec).collect::<Vec<_>>();
            assert_eq!(subnets.len(), subnets_per_custody_group as usize);
        }
    }
}

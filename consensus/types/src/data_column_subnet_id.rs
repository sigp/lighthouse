//! Identifies each data column subnet by an integer identifier.
use crate::data_column_sidecar::ColumnIndex;
use crate::{ChainSpec, EthSpec};
use alloy_primitives::U256;
use itertools::Itertools;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataColumnSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

impl DataColumnSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    pub fn from_column_index<E: EthSpec>(column_index: usize, spec: &ChainSpec) -> Self {
        (column_index
            .safe_rem(spec.data_column_sidecar_subnet_count as usize)
            .expect(
                "data_column_sidecar_subnet_count should never be zero if this function is called",
            ) as u64)
            .into()
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn columns<E: EthSpec>(&self, spec: &ChainSpec) -> impl Iterator<Item = ColumnIndex> {
        let subnet = self.0;
        let data_column_sidecar_subnet = spec.data_column_sidecar_subnet_count;
        let columns_per_subnet = spec.data_columns_per_subnet() as u64;
        (0..columns_per_subnet).map(move |i| data_column_sidecar_subnet * i + subnet)
    }

    /// Compute required subnets to subscribe to given the node id.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn compute_custody_subnets<E: EthSpec>(
        raw_node_id: [u8; 32],
        custody_subnet_count: u64,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = DataColumnSubnetId>, Error> {
        if custody_subnet_count > spec.data_column_sidecar_subnet_count {
            return Err(Error::InvalidCustodySubnetCount(custody_subnet_count));
        }

        let mut subnets: HashSet<u64> = HashSet::new();
        let mut current_id = U256::from_be_slice(&raw_node_id);
        while (subnets.len() as u64) < custody_subnet_count {
            let mut node_id_bytes = [0u8; 32];
            node_id_bytes.copy_from_slice(current_id.as_le_slice());
            let hash = ethereum_hashing::hash_fixed(&node_id_bytes);
            let hash_prefix: [u8; 8] = hash[0..8]
                .try_into()
                .expect("hash_fixed produces a 32 byte array");
            let hash_prefix_u64 = u64::from_le_bytes(hash_prefix);
            let subnet = hash_prefix_u64 % spec.data_column_sidecar_subnet_count;

            if !subnets.contains(&subnet) {
                subnets.insert(subnet);
            }

            if current_id == U256::MAX {
                current_id = U256::ZERO
            }
            current_id += U256::from(1u64)
        }
        Ok(subnets.into_iter().map(DataColumnSubnetId::new))
    }

    /// Compute the custody subnets for a given node id with the default `custody_requirement`.
    /// This operation should be infallable, and empty iterator is returned if it fails unexpectedly.
    pub fn compute_custody_requirement_subnets<E: EthSpec>(
        node_id: [u8; 32],
        spec: &ChainSpec,
    ) -> impl Iterator<Item = DataColumnSubnetId> {
        Self::compute_custody_subnets::<E>(node_id, spec.custody_requirement, spec)
            .expect("should compute default custody subnets")
    }

    pub fn compute_custody_columns<E: EthSpec>(
        raw_node_id: [u8; 32],
        custody_subnet_count: u64,
        spec: &ChainSpec,
    ) -> Result<impl Iterator<Item = ColumnIndex>, Error> {
        Self::compute_custody_subnets::<E>(raw_node_id, custody_subnet_count, spec)
            .map(|subnet| subnet.flat_map(|subnet| subnet.columns::<E>(spec)).sorted())
    }
}

impl Display for DataColumnSubnetId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Deref for DataColumnSubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DataColumnSubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for DataColumnSubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl From<DataColumnSubnetId> for u64 {
    fn from(val: DataColumnSubnetId) -> Self {
        val.0
    }
}

impl From<&DataColumnSubnetId> for u64 {
    fn from(val: &DataColumnSubnetId) -> Self {
        val.0
    }
}

#[derive(Debug)]
pub enum Error {
    ArithError(ArithError),
    InvalidCustodySubnetCount(u64),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

#[cfg(test)]
mod test {
    use crate::data_column_subnet_id::DataColumnSubnetId;
    use crate::MainnetEthSpec;
    use crate::Uint256;
    use crate::{EthSpec, GnosisEthSpec, MinimalEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn test_compute_subnets_for_data_column() {
        let spec = E::default_spec();
        let node_ids = [
            "0",
            "88752428858350697756262172400162263450541348766581994718383409852729519486397",
            "18732750322395381632951253735273868184515463718109267674920115648614659369468",
            "27726842142488109545414954493849224833670205008410190955613662332153332462900",
            "39755236029158558527862903296867805548949739810920318269566095185775868999998",
            "31899136003441886988955119620035330314647133604576220223892254902004850516297",
            "58579998103852084482416614330746509727562027284701078483890722833654510444626",
            "28248042035542126088870192155378394518950310811868093527036637864276176517397",
            "60930578857433095740782970114409273483106482059893286066493409689627770333527",
            "103822458477361691467064888613019442068586830412598673713899771287914656699997",
        ]
        .into_iter()
        .map(|v| Uint256::from_str_radix(v, 10).unwrap().to_be_bytes::<32>())
        .collect::<Vec<_>>();

        let custody_requirement = 4;
        for node_id in node_ids {
            let computed_subnets = DataColumnSubnetId::compute_custody_subnets::<E>(
                node_id,
                custody_requirement,
                &spec,
            )
            .unwrap();
            let computed_subnets: Vec<_> = computed_subnets.collect();

            // the number of subnets is equal to the custody requirement
            assert_eq!(computed_subnets.len() as u64, custody_requirement);

            let subnet_count = spec.data_column_sidecar_subnet_count;
            for subnet in computed_subnets {
                let columns: Vec<_> = subnet.columns::<E>(&spec).collect();
                // the number of columns is equal to the specified number of columns per subnet
                assert_eq!(columns.len(), spec.data_columns_per_subnet());

                for pair in columns.windows(2) {
                    // each successive column index is offset by the number of subnets
                    assert_eq!(pair[1] - pair[0], subnet_count);
                }
            }
        }
    }

    #[test]
    fn test_compute_custody_requirement_subnets_never_panics() {
        let node_id = [1u8; 32];
        test_compute_custody_requirement_subnets_with_spec::<MainnetEthSpec>(node_id);
        test_compute_custody_requirement_subnets_with_spec::<MinimalEthSpec>(node_id);
        test_compute_custody_requirement_subnets_with_spec::<GnosisEthSpec>(node_id);
    }

    fn test_compute_custody_requirement_subnets_with_spec<E: EthSpec>(node_id: [u8; 32]) {
        let _ = DataColumnSubnetId::compute_custody_requirement_subnets::<E>(
            node_id,
            &E::default_spec(),
        );
    }

    #[test]
    fn test_columns_subnet_conversion() {
        let spec = E::default_spec();
        for subnet in 0..spec.data_column_sidecar_subnet_count {
            let subnet_id = DataColumnSubnetId::new(subnet);
            for column_index in subnet_id.columns::<E>(&spec) {
                assert_eq!(
                    subnet_id,
                    DataColumnSubnetId::from_column_index::<E>(column_index as usize, &spec)
                );
            }
        }
    }
}

//! Identifies each data column subnet by an integer identifier.
use crate::EthSpec;
use ethereum_types::U256;
use safe_arith::{ArithError, SafeArith};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

const DATA_COLUMN_SUBNET_COUNT: u64 = 64;

lazy_static! {
    static ref DATA_COLUMN_SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(DATA_COLUMN_SUBNET_COUNT as usize);

        for i in 0..DATA_COLUMN_SUBNET_COUNT {
            v.push(i.to_string());
        }
        v
    };
}

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataColumnSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

pub fn data_column_subnet_id_to_string(i: u64) -> &'static str {
    if i < DATA_COLUMN_SUBNET_COUNT {
        DATA_COLUMN_SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below DATA_COLUMN_SUBNET_COUNT")
    } else {
        "data column subnet id out of range"
    }
}

impl DataColumnSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    pub fn try_from_column_index<T: EthSpec>(column_index: usize) -> Result<Self, Error> {
        let id = column_index.safe_rem(T::data_column_subnet_count())? as u64;
        Ok(id.into())
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn columns<T: EthSpec>(&self) -> impl Iterator<Item = u64> {
        let subnet = self.0;
        let data_column_subnet_count = T::data_column_subnet_count() as u64;
        let columns_per_subnet = (T::number_of_columns() as u64) / data_column_subnet_count;
        (0..columns_per_subnet).map(move |i| data_column_subnet_count * i + subnet)
    }

    /// Compute required subnets to subscribe to given the node id.
    /// TODO(das): Add epoch param
    #[allow(clippy::arithmetic_side_effects)]
    pub fn compute_custody_subnets<T: EthSpec>(
        node_id: U256,
        custody_subnet_count: u64,
    ) -> impl Iterator<Item = DataColumnSubnetId> {
        // NOTE: we could perform check on `custody_subnet_count` here to ensure that it is a valid
        // value, but here we assume it is valid.

        let mut subnets = SmallVec::<[u64; 32]>::new();
        let mut offset = 0;
        while (subnets.len() as u64) < custody_subnet_count {
            let offset_node_id = node_id + U256::from(offset);
            let offset_node_id = offset_node_id.as_u64().to_le_bytes();
            let hash = ethereum_hashing::hash_fixed(&offset_node_id);
            let subnet =
                U256::from_little_endian(&hash).as_u64() % (T::data_column_subnet_count() as u64);

            if !subnets.contains(&subnet) {
                subnets.push(subnet);
            }

            offset += 1
        }
        subnets.into_iter().map(DataColumnSubnetId::new)
    }

    pub fn compute_custody_columns<T: EthSpec>(
        node_id: U256,
        custody_subnet_count: u64,
    ) -> impl Iterator<Item = u64> {
        Self::compute_custody_subnets::<T>(node_id, custody_subnet_count)
            .flat_map(|subnet| subnet.columns::<T>())
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

impl Into<u64> for DataColumnSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &DataColumnSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for DataColumnSubnetId {
    fn as_ref(&self) -> &str {
        data_column_subnet_id_to_string(self.0)
    }
}

#[derive(Debug)]
pub enum Error {
    ArithError(ArithError),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

#[cfg(test)]
mod test {
    use crate::data_column_subnet_id::DataColumnSubnetId;
    use crate::ChainSpec;

    #[test]
    fn test_compute_subnets_for_data_column() {
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
        .map(|v| ethereum_types::U256::from_dec_str(v).unwrap())
        .collect::<Vec<_>>();

        let expected_subnets = vec![
            vec![0],
            vec![29],
            vec![28],
            vec![20],
            vec![30],
            vec![9],
            vec![18],
            vec![21],
            vec![23],
            vec![29],
        ];

        let spec = ChainSpec::mainnet();

        for x in 0..node_ids.len() {
            let computed_subnets = DataColumnSubnetId::compute_custody_subnets::<
                crate::MainnetEthSpec,
            >(node_ids[x], spec.custody_requirement);

            assert_eq!(
                expected_subnets[x],
                computed_subnets
                    .map(DataColumnSubnetId::into)
                    .collect::<Vec<u64>>()
            );
        }
    }
}

//! Identifies each blob column subnet by an integer identifier.
use crate::consts::deneb::BLOB_COLUMN_SUBNET_COUNT;
use crate::{ChainSpec, EthSpec};
use ethereum_types::U256;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};

lazy_static! {
    static ref BLOB_COLUMN_SUBNET_ID_TO_STRING: Vec<String> = {
        let mut v = Vec::with_capacity(BLOB_COLUMN_SUBNET_COUNT as usize);

        for i in 0..BLOB_COLUMN_SUBNET_COUNT {
            v.push(i.to_string());
        }
        v
    };
}

#[derive(arbitrary::Arbitrary, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobColumnSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

pub fn blob_column_subnet_id_to_string(i: u64) -> &'static str {
    if i < BLOB_COLUMN_SUBNET_COUNT {
        BLOB_COLUMN_SUBNET_ID_TO_STRING
            .get(i as usize)
            .expect("index below BLOB_COLUMN_SUBNET_COUNT")
    } else {
        "blob column subnet id out of range"
    }
}

impl BlobColumnSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    #[allow(clippy::arithmetic_side_effects)]
    /// Compute required subnets to subscribe to given the node id.
    /// TODO(das): Add epoch param
    pub fn compute_subnets_for_blob_column<T: EthSpec>(
        node_id: U256,
        spec: &ChainSpec,
    ) -> impl Iterator<Item = BlobColumnSubnetId> {
        let num_of_columns = T::number_of_blob_columns() as u64;
        (0..spec.blob_custody_requirement)
            .map(move |i| {
                let node_offset = (node_id % U256::from(num_of_columns)).as_u64();
                node_offset.saturating_add(i) % num_of_columns
            })
            .map(BlobColumnSubnetId::new)
    }
}

impl Display for BlobColumnSubnetId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl Deref for BlobColumnSubnetId {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BlobColumnSubnetId {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<u64> for BlobColumnSubnetId {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Into<u64> for BlobColumnSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &BlobColumnSubnetId {
    fn into(self) -> u64 {
        self.0
    }
}

impl AsRef<str> for BlobColumnSubnetId {
    fn as_ref(&self) -> &str {
        blob_column_subnet_id_to_string(self.0)
    }
}

#[cfg(test)]
mod test {
    use crate::blob_column_subnet_id::BlobColumnSubnetId;
    use crate::ChainSpec;

    #[test]
    fn test_compute_subnets_for_blob_column() {
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
            vec![0, 1],
            vec![61, 62],
            vec![124, 125],
            vec![52, 53],
            vec![62, 63],
            vec![73, 74],
            vec![82, 83],
            vec![21, 22],
            vec![87, 88],
            vec![93, 94],
        ];

        let spec = ChainSpec::mainnet();

        for x in 0..node_ids.len() {
            let computed_subnets = BlobColumnSubnetId::compute_subnets_for_blob_column::<
                crate::MainnetEthSpec,
            >(node_ids[x], &spec);

            assert_eq!(
                expected_subnets[x],
                computed_subnets
                    .map(BlobColumnSubnetId::into)
                    .collect::<Vec<u64>>()
            );
        }
    }
}

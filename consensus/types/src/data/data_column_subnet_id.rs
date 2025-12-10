//! Identifies each data column subnet by an integer identifier.
use std::{
    fmt::{self, Display},
    ops::{Deref, DerefMut},
};

use safe_arith::SafeArith;
use serde::{Deserialize, Serialize};

use crate::{core::ChainSpec, data::ColumnIndex};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataColumnSubnetId(#[serde(with = "serde_utils::quoted_u64")] u64);

impl fmt::Debug for DataColumnSubnetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl DataColumnSubnetId {
    pub fn new(id: u64) -> Self {
        id.into()
    }

    pub fn from_column_index(column_index: ColumnIndex, spec: &ChainSpec) -> Self {
        column_index
            .safe_rem(spec.data_column_sidecar_subnet_count)
            .expect(
                "data_column_sidecar_subnet_count should never be zero if this function is called",
            )
            .into()
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

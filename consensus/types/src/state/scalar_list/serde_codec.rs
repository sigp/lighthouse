use context_deserialize::ContextDeserialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use silver_hashing::{HashFormat, SszScalar};
use typenum::Unsigned;

use super::ScalarList;

impl<T: SszScalar, N: Unsigned> ScalarList<T, N> {
    pub(super) fn deserialize_as<E: serde::de::Error>(
        values: Vec<T>,
        format: HashFormat,
    ) -> Result<Self, E> {
        Self::new(values, format).map_err(|_| E::custom("list longer than SSZ limit"))
    }
}

impl<T: SszScalar + Serialize, N: Unsigned> Serialize for ScalarList<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<'de, T: SszScalar + Deserialize<'de>, N: Unsigned> Deserialize<'de> for ScalarList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::deserialize_as(Vec::deserialize(deserializer)?, HashFormat::Fixed)
    }
}

impl<'de, C, T: SszScalar + Deserialize<'de>, N: Unsigned> ContextDeserialize<'de, C>
    for ScalarList<T, N>
{
    fn context_deserialize<D: Deserializer<'de>>(
        deserializer: D,
        _context: C,
    ) -> Result<Self, D::Error> {
        Self::deserialize(deserializer)
    }
}

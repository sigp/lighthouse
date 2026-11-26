//! `ssz_types::serde_utils::quoted_u64_var_list` for a list that yields values,
//! not references.

use serde::{Deserializer, Serializer};
use silver_hashing::HashFormat;
use typenum::Unsigned;

use super::ScalarList;

pub fn serialize<N: Unsigned, S: Serializer>(
    list: &ScalarList<u64, N>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(list.iter().map(|v| v.to_string()))
}

pub fn deserialize<'de, N: Unsigned, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ScalarList<u64, N>, D::Error> {
    ScalarList::deserialize_as(
        serde_utils::quoted_u64_vec::deserialize(deserializer)?,
        HashFormat::Fixed,
    )
}

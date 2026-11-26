//! `#[ssz(with)]` and `#[serde(with)]` for a field that hashes as
//! `ProgressiveList[T]`: decode builds that format directly.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use silver_hashing::{HashFormat, SszScalar};
use typenum::Unsigned;

use super::ScalarList;

pub mod encode {
    use silver_hashing::SszScalar;
    pub use ssz::Encode;
    use typenum::Unsigned;

    use super::ScalarList;

    pub fn is_ssz_fixed_len() -> bool {
        false
    }

    pub fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }

    pub fn ssz_bytes_len<T: SszScalar, N: Unsigned>(list: &ScalarList<T, N>) -> usize {
        list.ssz_bytes_len()
    }

    pub fn ssz_append<T: SszScalar, N: Unsigned>(list: &ScalarList<T, N>, buf: &mut Vec<u8>) {
        list.ssz_append(buf)
    }
}

pub mod decode {
    use silver_hashing::{HashFormat, SszScalar};
    use ssz::DecodeError;
    use typenum::Unsigned;

    use super::ScalarList;

    pub fn is_ssz_fixed_len() -> bool {
        false
    }

    pub fn ssz_fixed_len() -> usize {
        ssz::BYTES_PER_LENGTH_OFFSET
    }

    pub fn from_ssz_bytes<T: SszScalar, N: Unsigned>(
        bytes: &[u8],
    ) -> Result<ScalarList<T, N>, DecodeError> {
        ScalarList::from_ssz_bytes_as(bytes, HashFormat::Progressive)
    }
}

/// Quoted serde, like `scalar_list::quoted_u64`.
pub mod quoted_u64 {
    pub use crate::state::scalar_list::quoted_u64::serialize;
    use serde::Deserializer;
    use silver_hashing::HashFormat;
    use typenum::Unsigned;

    use super::ScalarList;

    pub fn deserialize<'de, N: Unsigned, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ScalarList<u64, N>, D::Error> {
        ScalarList::deserialize_as(
            serde_utils::quoted_u64_vec::deserialize(deserializer)?,
            HashFormat::Progressive,
        )
    }
}

pub fn serialize<T: SszScalar + Serialize, N: Unsigned, S: Serializer>(
    list: &ScalarList<T, N>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    list.serialize(serializer)
}

pub fn deserialize<'de, T: SszScalar + Deserialize<'de>, N: Unsigned, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<ScalarList<T, N>, D::Error> {
    ScalarList::deserialize_as(Vec::deserialize(deserializer)?, HashFormat::Progressive)
}

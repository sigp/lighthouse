use serde_derive::Deserialize;
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::convert::TryFrom;
use std::fmt::Debug;
use tree_hash::TreeHash;
use types::ForkName;

/// Macro to wrap U128 and U256 so they deserialize correctly.
macro_rules! uint_wrapper {
    ($wrapper_name:ident, $wrapped_type:ty) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Decode, Encode, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $wrapper_name {
            pub x: $wrapped_type,
        }

        impl TryFrom<String> for $wrapper_name {
            type Error = String;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                <$wrapped_type>::from_dec_str(&s)
                    .map(|x| Self { x })
                    .map_err(|e| format!("{:?}", e))
            }
        }

        impl tree_hash::TreeHash for $wrapper_name {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                <$wrapped_type>::tree_hash_type()
            }

            fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
                self.x.tree_hash_packed_encoding()
            }

            fn tree_hash_packing_factor() -> usize {
                <$wrapped_type>::tree_hash_packing_factor()
            }

            fn tree_hash_root(&self) -> tree_hash::Hash256 {
                self.x.tree_hash_root()
            }
        }
    };
}

uint_wrapper!(TestU128, ethereum_types::U128);
uint_wrapper!(TestU256, ethereum_types::U256);

/// Trait for types that can be used in SSZ static tests.
pub trait SszStaticType:
    serde::de::DeserializeOwned + Encode + TreeHash + Clone + PartialEq + Debug + Sync
{
}

impl<T> SszStaticType for T where
    T: serde::de::DeserializeOwned + Encode + TreeHash + Clone + PartialEq + Debug + Sync
{
}

/// Return the fork immediately prior to a fork.
pub fn previous_fork(fork_name: ForkName) -> ForkName {
    match fork_name {
        ForkName::Base => ForkName::Base,
        ForkName::Altair => ForkName::Base,
        ForkName::Merge => ForkName::Altair, // TODO: Check this when tests are released..
        ForkName::Capella => ForkName::Merge, // TODO: Check this when tests are released..
    }
}

#[macro_export]
macro_rules! impl_bls_load_case {
    ($case_name:ident) => {
        use $crate::decode::yaml_decode_file;
        impl LoadCase for $case_name {
            fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
                yaml_decode_file(&path)
            }
        }
    };

    ($case_name:ident, $sub_path_name:expr) => {
        use $crate::decode::yaml_decode_file;
        impl LoadCase for $case_name {
            fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
                yaml_decode_file(&path.join($sub_path_name))
            }
        }
    };
}

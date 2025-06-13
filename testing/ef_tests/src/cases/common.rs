use context_deserialize::ContextDeserialize;
use serde::{Deserialize, Deserializer};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use std::marker::PhantomData;
use tree_hash::TreeHash;
use types::{DataColumnsByRootIdentifier, EthSpec, ForkName, Hash256};

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
                <$wrapped_type>::from_str_radix(&s, 10)
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

        impl<'de, T> ContextDeserialize<'de, T> for $wrapper_name {
            fn context_deserialize<D>(deserializer: D, _context: T) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                <$wrapper_name>::deserialize(deserializer)
            }
        }
    };
}

uint_wrapper!(DecimalU128, alloy_primitives::U128);
uint_wrapper!(DecimalU256, alloy_primitives::U256);

/// Trait for types that can be used in SSZ static tests.
pub trait SszStaticType: Encode + Clone + PartialEq + Debug + Sync {}

impl<T> SszStaticType for T where T: Encode + Clone + PartialEq + Debug + Sync {}

/// We need the `EthSpec` to implement `LoadCase` for this type, in order to work out the
/// ChainSpec.
///
/// No other type currently requires this kind of context.
#[derive(Debug, Encode, Clone, PartialEq)]
#[ssz(struct_behaviour = "transparent")]
pub struct DataColumnsByRootIdentifierWrapper<E: EthSpec> {
    pub value: DataColumnsByRootIdentifier,
    // SSZ derive is a bit buggy and requires skip_deserializing for transparent to work.
    #[ssz(skip_serializing, skip_deserializing)]
    pub _phantom: PhantomData<E>,
}

impl<'de, E: EthSpec> ContextDeserialize<'de, (ForkName, usize)>
    for DataColumnsByRootIdentifierWrapper<E>
{
    fn context_deserialize<D>(deserializer: D, context: (ForkName, usize)) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = DataColumnsByRootIdentifier::context_deserialize(deserializer, context)?;
        Ok(DataColumnsByRootIdentifierWrapper {
            value,
            _phantom: PhantomData,
        })
    }
}

// We can delete this if we ever get `tree_hash(struct_behaviour = "transparent")`.
impl<E: EthSpec> TreeHash for DataColumnsByRootIdentifierWrapper<E> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        DataColumnsByRootIdentifier::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.value.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        DataColumnsByRootIdentifier::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.value.tree_hash_root()
    }
}

impl<E: EthSpec> From<DataColumnsByRootIdentifier> for DataColumnsByRootIdentifierWrapper<E> {
    fn from(value: DataColumnsByRootIdentifier) -> Self {
        Self {
            value,
            _phantom: PhantomData,
        }
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

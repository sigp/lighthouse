#![allow(non_snake_case)]

use super::*;
use crate::cases::common::{DecimalU128, DecimalU256, SszStaticType};
use crate::cases::ssz_static::{check_serialization, check_tree_hash};
use crate::decode::{context_yaml_decode_file, log_file_access, snappy_decode_file};
use context_deserialize::{ContextDeserialize, context_deserialize};
use serde::{Deserialize, Deserializer, de::Error as SerdeError};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::typenum::*;
use types::{BitList, BitVector, FixedVector, ForkName, VariableList, Vector};

#[derive(Debug, Clone, Deserialize)]
#[context_deserialize(ForkName)]
struct Metadata {
    root: String,
    #[serde(rename(deserialize = "signing_root"))]
    _signing_root: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SszGeneric {
    path: PathBuf,
    handler_name: String,
    case_name: String,
}

impl LoadCase for SszGeneric {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        let components = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .rev()
            .collect::<Vec<_>>();
        // Test case name is last
        let case_name = components[0].clone();
        // Handler name is third last, before suite name and case name
        let handler_name = components[2].clone();
        Ok(Self {
            path: path.into(),
            handler_name,
            case_name,
        })
    }
}

macro_rules! type_dispatch {
    ($function:ident,
     ($($arg:expr),*),
     $base_ty:tt,
     <$($param_ty:ty),*>,
     [ $value:expr => primitive_type ] $($rest:tt)*) => {
        match $value {
            "bool" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* bool>, $($rest)*),
            "uint8" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* u8>, $($rest)*),
            "uint16" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* u16>, $($rest)*),
            "uint32" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* u32>, $($rest)*),
            "uint64" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* u64>, $($rest)*),
            "uint128" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* DecimalU128>, $($rest)*),
            "uint256" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* DecimalU256>, $($rest)*),
            _ => Err(Error::FailedToParseTest(format!("unsupported: {}", $value))),
        }
    };
    ($function:ident,
     ($($arg:expr),*),
     $base_ty:tt,
     <$($param_ty:ty),*>,
     [ $value:expr => typenum ] $($rest:tt)*) => {
        match $value {
            // DO YOU LIKE NUMBERS?
            "0" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U0>, $($rest)*),
            "1" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U1>, $($rest)*),
            "2" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U2>, $($rest)*),
            "3" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U3>, $($rest)*),
            "4" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U4>, $($rest)*),
            "5" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U5>, $($rest)*),
            "6" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U6>, $($rest)*),
            "7" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U7>, $($rest)*),
            "8" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U8>, $($rest)*),
            "9" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U9>, $($rest)*),
            "15" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U15>, $($rest)*),
            "16" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U16>, $($rest)*),
            "17" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U17>, $($rest)*),
            "31" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U31>, $($rest)*),
            "32" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U32>, $($rest)*),
            "33" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U33>, $($rest)*),
            "64" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U64>, $($rest)*),
            "128" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U128>, $($rest)*),
            "256" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U256>, $($rest)*),
            "511" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U511>, $($rest)*),
            "512" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U512>, $($rest)*),
            "513" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U513>, $($rest)*),
            "1024" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U1024>, $($rest)*),
            "2048" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U2048>, $($rest)*),
            "4096" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U4096>, $($rest)*),
            "8192" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* U8192>, $($rest)*),
            _ => Err(Error::FailedToParseTest(format!("unsupported: {}", $value))),
        }
    };
    ($function:ident,
     ($($arg:expr),*),
     $base_ty:tt,
     <$($param_ty:ty),*>,
     [ $value:expr => test_container ] $($rest:tt)*) => {
        match $value {
            "SingleFieldTestStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* SingleFieldTestStruct>, $($rest)*),
            "SmallTestStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* SmallTestStruct>, $($rest)*),
            "FixedTestStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* FixedTestStruct>, $($rest)*),
            "VarTestStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* VarTestStruct>, $($rest)*),
            "ComplexTestStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* ComplexTestStruct>, $($rest)*),
            "BitsStruct" => type_dispatch!($function, ($($arg),*), $base_ty, <$($param_ty,)* BitsStruct>, $($rest)*),
            // EIP-7916 is still in draft and hasn't been implemented yet https://eips.ethereum.org/EIPS/eip-7916
            "ProgressiveTestStruct" | "ProgressiveBitsStruct" => Err(Error::SkippedKnownFailure),
            _ => Err(Error::FailedToParseTest(format!("unsupported: {}", $value))),
        }
    };
    // No base type: apply type params to function
    ($function:ident, ($($arg:expr),*), _, <$($param_ty:ty),*>,) => {
        $function::<$($param_ty),*>($($arg),*)
    };
    ($function:ident, ($($arg:expr),*), $base_type_name:ident, <$($param_ty:ty),*>,) => {
        $function::<$base_type_name<$($param_ty),*>>($($arg),*)
    }
}

impl Case for SszGeneric {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let parts = self.case_name.split('_').collect::<Vec<_>>();

        match self.handler_name.as_str() {
            "basic_vector" => {
                let elem_ty = parts[1];
                let length = parts[2];

                // Skip length 0 tests. Milhouse doesn't have any checks against 0-capacity lists.
                if length == "0" {
                    log_file_access(self.path.join("serialized.ssz_snappy"));
                    return Ok(());
                }

                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    Vector,
                    <>,
                    [elem_ty => primitive_type]
                    [length => typenum]
                )?;
                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    FixedVector,
                    <>,
                    [elem_ty => primitive_type]
                    [length => typenum]
                )?;
            }
            "bitlist" => {
                let mut limit = parts[1];

                // Test format is inconsistent, pretend the limit is 32 (arbitrary)
                if limit == "no" {
                    limit = "32";
                }

                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    BitList,
                    <>,
                    [limit => typenum]
                )?;
            }
            "bitvector" => {
                let length = parts[1];

                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    BitVector,
                    <>,
                    [length => typenum]
                )?;
            }
            "boolean" => {
                ssz_generic_test::<bool>(&self.path, fork_name)?;
            }
            "uints" => {
                let type_name = "uint".to_owned() + parts[1];

                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    _,
                    <>,
                    [type_name.as_str() => primitive_type]
                )?;
            }
            "containers" => {
                let type_name = parts[0];

                type_dispatch!(
                    ssz_generic_test,
                    (&self.path, fork_name),
                    _,
                    <>,
                    [type_name => test_container]
                )?;
            }
            _ => panic!("unsupported handler: {}", self.handler_name),
        }
        Ok(())
    }
}

fn ssz_generic_test<
    T: SszStaticType + for<'de> ContextDeserialize<'de, ForkName> + TreeHash + ssz::Decode,
>(
    path: &Path,
    fork_name: ForkName,
) -> Result<(), Error> {
    let meta_path = path.join("meta.yaml");
    let meta: Option<Metadata> = if meta_path.is_file() {
        Some(context_yaml_decode_file(&meta_path, fork_name)?)
    } else {
        None
    };

    let serialized = snappy_decode_file(&path.join("serialized.ssz_snappy"))
        .expect("serialized.ssz_snappy exists");

    let value_path = path.join("value.yaml");
    let value: Option<T> = if value_path.is_file() {
        Some(context_yaml_decode_file(&value_path, fork_name)?)
    } else {
        None
    };

    // Valid
    // TODO: signing root (annoying because of traits)
    if let Some(value) = value {
        check_serialization(&value, &serialized, T::from_ssz_bytes)?;

        if let Some(ref meta) = meta {
            check_tree_hash(&meta.root, value.tree_hash_root().as_slice())?;
        }
    }
    // Invalid
    else if let Ok(decoded) = T::from_ssz_bytes(&serialized) {
        return Err(Error::DidntFail(format!(
            "Decoded invalid bytes into: {:?}",
            decoded
        )));
    }
    Ok(())
}

// Containers for SSZ generic tests
#[derive(Debug, Clone, Default, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct SingleFieldTestStruct {
    A: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct SmallTestStruct {
    A: u16,
    B: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct FixedTestStruct {
    A: u8,
    B: u64,
    C: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct VarTestStruct {
    A: u16,
    B: VariableList<u16, U1024>,
    C: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct ComplexTestStruct {
    A: u16,
    B: VariableList<u16, U128>,
    C: u8,
    #[serde(deserialize_with = "byte_list_from_hex_str")]
    D: VariableList<u8, U256>,
    E: VarTestStruct,
    F: Vector<FixedTestStruct, U4>,
    G: Vector<VarTestStruct, U2>,
}

#[derive(Debug, Clone, PartialEq, Decode, Encode, TreeHash, Deserialize)]
#[context_deserialize(ForkName)]
struct BitsStruct {
    A: BitList<U5>,
    B: BitVector<U2>,
    C: BitVector<U1>,
    D: BitList<U6>,
    E: BitVector<U8>,
}

fn byte_list_from_hex_str<'de, D, N: Unsigned>(
    deserializer: D,
) -> Result<VariableList<u8, N>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = serde::de::Deserialize::deserialize(deserializer)?;
    let decoded: Vec<u8> = hex::decode(&s.as_str()[2..]).map_err(D::Error::custom)?;

    if decoded.len() > N::to_usize() {
        Err(D::Error::custom(format!(
            "Too many values for list, got: {}, limit: {}",
            decoded.len(),
            N::to_usize()
        )))
    } else {
        Ok(decoded.into())
    }
}

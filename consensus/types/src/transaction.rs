use crate::{Hash256, Uint256, VersionedHash};
use ethereum_types::Address;
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U16777216, U4096};
use ssz_types::VariableList;

pub type MaxCalldataSize = U16777216;
pub type MaxAccessListSize = U16777216;
pub type MaxAccessListStorageKeys = U16777216;
pub type MaxVersionedHashesListSize = U4096;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SignedBlobTransaction {
    pub message: BlobTransaction,
    pub signature: EcdsaSignature,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct BlobTransaction {
    pub chain_id: Uint256,
    pub nonce: u64,
    pub max_priority_fee_per_gas: Uint256,
    pub max_fee_per_gas: Uint256,
    pub gas: u64,
    pub to: Option<Address>,
    pub value: Uint256,
    pub data: VariableList<u8, MaxCalldataSize>,
    pub access_list: VariableList<AccessTuple, MaxAccessListSize>,
    pub max_fee_per_data_gas: Uint256,
    pub versioned_hashes: VariableList<VersionedHash, MaxVersionedHashesListSize>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct AccessTuple {
    pub address: Address,
    pub storage_keys: VariableList<Hash256, MaxAccessListStorageKeys>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct EcdsaSignature {
    pub y_parity: bool,
    pub r: Uint256,
    pub s: Uint256,
}

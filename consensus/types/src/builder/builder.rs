use crate::{Address, BeaconStateError, ChainSpec, Epoch, ForkName, Hash256};
use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

pub type BuilderIndex = u64;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct Builder {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u8")]
    pub version: u8,
    pub execution_address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub balance: u64,
    pub deposit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl Builder {
    /// Construct a new registry entry from deposit data, extracting the execution address
    /// from the withdrawal credentials.
    pub fn from_deposit(
        pubkey: PublicKeyBytes,
        version: u8,
        withdrawal_credentials: Hash256,
        amount: u64,
        deposit_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let execution_address = withdrawal_credentials
            .as_slice()
            .get(12..)
            .and_then(|bytes| Address::try_from(bytes).ok())
            .ok_or(BeaconStateError::WithdrawalCredentialMissingAddress)?;

        Ok(Self {
            pubkey,
            version,
            execution_address,
            balance: amount,
            deposit_epoch,
            withdrawable_epoch: spec.far_future_epoch,
        })
    }
}

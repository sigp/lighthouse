use crate::engines::ForkChoiceState;
pub use ethers_core::types::Transaction;
use ethers_core::utils::rlp::{Decodable, Rlp};
use http::deposit_methods::RpcError;
pub use json_structures::TransitionConfigurationV1;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;
use superstruct::superstruct;
use types::Withdrawal;
pub use types::{
    Address, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader, FixedVector,
    Hash256, Uint256, VariableList,
};

pub mod auth;
pub mod http;
pub mod json_structures;

pub const LATEST_TAG: &str = "latest";

pub type PayloadId = [u8; 8];

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Auth(auth::Error),
    BadResponse(String),
    RequestFailed(String),
    InvalidExecutePayloadResponse(&'static str),
    JsonRpc(RpcError),
    Json(serde_json::Error),
    ServerMessage { code: i64, message: String },
    Eip155Failure,
    IsSyncing,
    ExecutionBlockNotFound(ExecutionBlockHash),
    ExecutionHeadBlockNotFound,
    ParentHashEqualsBlockHash(ExecutionBlockHash),
    PayloadIdUnavailable,
    TransitionConfigurationMismatch,
    PayloadConversionLogicFlaw,
    DeserializeTransaction(ssz_types::Error),
    DeserializeTransactions(ssz_types::Error),
    DeserializeWithdrawals(ssz_types::Error),
    BuilderApi(builder_client::Error),
    IncorrectStateVariant,
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        if matches!(
            e.status(),
            Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN)
        ) {
            Error::Auth(auth::Error::InvalidToken)
        } else {
            Error::Reqwest(e)
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<auth::Error> for Error {
    fn from(e: auth::Error) -> Self {
        Error::Auth(e)
    }
}

impl From<builder_client::Error> for Error {
    fn from(e: builder_client::Error) -> Self {
        Error::BuilderApi(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum PayloadStatusV1Status {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    InvalidBlockHash,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PayloadStatusV1 {
    pub status: PayloadStatusV1Status,
    pub latest_valid_hash: Option<ExecutionBlockHash>,
    pub validation_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BlockByNumberQuery<'a> {
    Tag(&'a str),
}

/// Representation of an exection block with enough detail to determine the terminal PoW block.
///
/// See `get_pow_block_hash_at_total_difficulty`.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionBlock {
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
}

/// Representation of an execution block with enough detail to reconstruct a payload.
#[superstruct(
    variants(Merge, Capella),
    variant_attributes(
        derive(Clone, Debug, PartialEq, Serialize, Deserialize,),
        serde(bound = "T: EthSpec", rename_all = "camelCase"),
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec", rename_all = "camelCase", untagged)]
pub struct ExecutionBlockWithTransactions<T: EthSpec> {
    pub parent_hash: ExecutionBlockHash,
    #[serde(alias = "miner")]
    pub fee_recipient: Address,
    pub state_root: Hash256,
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, T::BytesPerLogsBloom>,
    #[serde(alias = "mixHash")]
    pub prev_randao: Hash256,
    #[serde(rename = "number", with = "eth2_serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    #[cfg(feature = "eip4844")]
    #[superstruct(only(Capella))]
    #[serde(with = "eth2_serde_utils::u64_hex_be")]
    pub excess_blobs: u64,
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    pub transactions: Vec<Transaction>,
    #[cfg(feature = "withdrawals")]
    #[superstruct(only(Capella))]
    pub withdrawals: Vec<Withdrawal>,
}

impl<T: EthSpec> From<ExecutionPayload<T>> for ExecutionBlockWithTransactions<T> {
    fn from(payload: ExecutionPayload<T>) -> Self {
        match payload {
            ExecutionPayload::Merge(block) => Self::Merge(ExecutionBlockWithTransactionsMerge {
                parent_hash: block.parent_hash,
                fee_recipient: block.fee_recipient,
                state_root: block.state_root,
                receipts_root: block.receipts_root,
                logs_bloom: block.logs_bloom,
                prev_randao: block.prev_randao,
                block_number: block.block_number,
                gas_limit: block.gas_limit,
                gas_used: block.gas_used,
                timestamp: block.timestamp,
                extra_data: block.extra_data,
                base_fee_per_gas: block.base_fee_per_gas,
                block_hash: block.block_hash,
                transactions: block
                    .transactions
                    .iter()
                    .map(|tx| Transaction::decode(&Rlp::new(tx)))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap_or_else(|_| Vec::new()),
            }),
            ExecutionPayload::Capella(block) => {
                Self::Capella(ExecutionBlockWithTransactionsCapella {
                    parent_hash: block.parent_hash,
                    fee_recipient: block.fee_recipient,
                    state_root: block.state_root,
                    receipts_root: block.receipts_root,
                    logs_bloom: block.logs_bloom,
                    prev_randao: block.prev_randao,
                    block_number: block.block_number,
                    gas_limit: block.gas_limit,
                    gas_used: block.gas_used,
                    timestamp: block.timestamp,
                    extra_data: block.extra_data,
                    base_fee_per_gas: block.base_fee_per_gas,
                    #[cfg(feature = "eip4844")]
                    excess_blobs: block.excess_blobs,
                    block_hash: block.block_hash,
                    transactions: block
                        .transactions
                        .iter()
                        .map(|tx| Transaction::decode(&Rlp::new(tx)))
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_else(|_| Vec::new()),
                    #[cfg(feature = "withdrawals")]
                    withdrawals: block.withdrawals.into(),
                })
            }
        }
    }
}

#[superstruct(
    variants(V1, V2),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct PayloadAttributes {
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[superstruct(getter(copy))]
    pub suggested_fee_recipient: Address,
    #[cfg(feature = "withdrawals")]
    #[superstruct(only(V2))]
    pub withdrawals: Vec<Withdrawal>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ForkchoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<PayloadId>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProposeBlindedBlockResponseStatus {
    Valid,
    Invalid,
    Syncing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProposeBlindedBlockResponse {
    pub status: ProposeBlindedBlockResponseStatus,
    pub latest_valid_hash: Option<Hash256>,
    pub validation_error: Option<String>,
}

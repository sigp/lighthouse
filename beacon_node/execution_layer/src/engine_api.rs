use crate::engines::ForkchoiceState;
use crate::http::{
    ENGINE_FORKCHOICE_UPDATED_V1, ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_FORKCHOICE_UPDATED_V3,
    ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1, ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1,
    ENGINE_GET_PAYLOAD_V1, ENGINE_GET_PAYLOAD_V2, ENGINE_GET_PAYLOAD_V3, ENGINE_NEW_PAYLOAD_V1,
    ENGINE_NEW_PAYLOAD_V2, ENGINE_NEW_PAYLOAD_V3,
};
use eth2::types::{
    BlobsBundle, SsePayloadAttributes, SsePayloadAttributesV1, SsePayloadAttributesV2,
    SsePayloadAttributesV3,
};
use ethers_core::types::Transaction;
use ethers_core::utils::rlp;
use ethers_core::utils::rlp::{Decodable, Rlp};
use http::deposit_methods::RpcError;
pub use json_structures::{JsonWithdrawal, TransitionConfigurationV1};
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::convert::TryFrom;
use strum::IntoStaticStr;
use superstruct::superstruct;
pub use types::{
    Address, BeaconBlockRef, EthSpec, ExecutionBlockHash, ExecutionPayload, ExecutionPayloadHeader,
    ExecutionPayloadRef, FixedVector, ForkName, Hash256, Transactions, Uint256, VariableList,
    Withdrawal, Withdrawals,
};
use types::{
    BeaconStateError, ExecutionPayloadCapella, ExecutionPayloadDeneb, ExecutionPayloadMerge,
    KzgProofs, VersionedHash,
};

pub mod auth;
pub mod http;
pub mod json_structures;

pub const LATEST_TAG: &str = "latest";

pub type PayloadId = [u8; 8];

#[derive(Debug)]
pub enum Error {
    HttpClient(PrettyReqwestError),
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
    SszError(ssz_types::Error),
    DeserializeWithdrawals(ssz_types::Error),
    BuilderApi(builder_client::Error),
    IncorrectStateVariant,
    RequiredMethodUnsupported(&'static str),
    UnsupportedForkVariant(String),
    RlpDecoderError(rlp::DecoderError),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        if matches!(
            e.status(),
            Some(StatusCode::UNAUTHORIZED) | Some(StatusCode::FORBIDDEN)
        ) {
            Error::Auth(auth::Error::InvalidToken)
        } else {
            Error::HttpClient(e.into())
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

impl From<rlp::DecoderError> for Error {
    fn from(e: rlp::DecoderError) -> Self {
        Error::RlpDecoderError(e)
    }
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::SszError(e)
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
    #[serde(rename = "number", with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    pub parent_hash: ExecutionBlockHash,
    pub total_difficulty: Uint256,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
}

/// Representation of an execution block with enough detail to reconstruct a payload.
#[superstruct(
    variants(Merge, Capella, Deneb),
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
    #[serde(rename = "number", with = "serde_utils::u64_hex_be")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64_hex_be")]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, T::MaxExtraDataBytes>,
    pub base_fee_per_gas: Uint256,
    #[serde(rename = "hash")]
    pub block_hash: ExecutionBlockHash,
    pub transactions: Vec<Transaction>,
    #[superstruct(only(Capella, Deneb))]
    pub withdrawals: Vec<JsonWithdrawal>,
    #[superstruct(only(Deneb))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb))]
    #[serde(with = "serde_utils::u64_hex_be")]
    pub excess_blob_gas: u64,
}

impl<T: EthSpec> TryFrom<ExecutionPayload<T>> for ExecutionBlockWithTransactions<T> {
    type Error = Error;

    fn try_from(payload: ExecutionPayload<T>) -> Result<Self, Error> {
        let json_payload = match payload {
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
                    .collect::<Result<Vec<_>, _>>()?,
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
                    block_hash: block.block_hash,
                    transactions: block
                        .transactions
                        .iter()
                        .map(|tx| Transaction::decode(&Rlp::new(tx)))
                        .collect::<Result<Vec<_>, _>>()?,
                    withdrawals: Vec::from(block.withdrawals)
                        .into_iter()
                        .map(|withdrawal| withdrawal.into())
                        .collect(),
                })
            }
            ExecutionPayload::Deneb(block) => Self::Deneb(ExecutionBlockWithTransactionsDeneb {
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
                    .collect::<Result<Vec<_>, _>>()?,
                withdrawals: Vec::from(block.withdrawals)
                    .into_iter()
                    .map(|withdrawal| withdrawal.into())
                    .collect(),
                blob_gas_used: block.blob_gas_used,
                excess_blob_gas: block.excess_blob_gas,
            }),
        };
        Ok(json_payload)
    }
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Eq, Hash, PartialEq),),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PayloadAttributes {
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[superstruct(getter(copy))]
    pub suggested_fee_recipient: Address,
    #[superstruct(only(V2, V3))]
    pub withdrawals: Vec<Withdrawal>,
    #[superstruct(only(V3), partial_getter(copy))]
    pub parent_beacon_block_root: Hash256,
}

impl PayloadAttributes {
    pub fn new(
        timestamp: u64,
        prev_randao: Hash256,
        suggested_fee_recipient: Address,
        withdrawals: Option<Vec<Withdrawal>>,
        parent_beacon_block_root: Option<Hash256>,
    ) -> Self {
        match withdrawals {
            Some(withdrawals) => match parent_beacon_block_root {
                Some(parent_beacon_block_root) => PayloadAttributes::V3(PayloadAttributesV3 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                    parent_beacon_block_root,
                }),
                None => PayloadAttributes::V2(PayloadAttributesV2 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient,
                    withdrawals,
                }),
            },
            None => PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }),
        }
    }
}

impl From<PayloadAttributes> for SsePayloadAttributes {
    fn from(pa: PayloadAttributes) -> Self {
        match pa {
            PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }) => Self::V1(SsePayloadAttributesV1 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            }),
            PayloadAttributes::V2(PayloadAttributesV2 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
            }) => Self::V2(SsePayloadAttributesV2 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
            }),
            PayloadAttributes::V3(PayloadAttributesV3 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
                parent_beacon_block_root,
            }) => Self::V3(SsePayloadAttributesV3 {
                timestamp,
                prev_randao,
                suggested_fee_recipient,
                withdrawals,
                parent_beacon_block_root,
            }),
        }
    }
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

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct GetPayloadResponse<T: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadMerge<T>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<T>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<T>,
    pub block_value: Uint256,
    #[superstruct(only(Deneb))]
    pub blobs_bundle: BlobsBundle<T>,
    #[superstruct(only(Deneb), partial_getter(copy))]
    pub should_override_builder: bool,
}

impl<E: EthSpec> GetPayloadResponse<E> {
    pub fn fee_recipient(&self) -> Address {
        ExecutionPayloadRef::from(self.to_ref()).fee_recipient()
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        ExecutionPayloadRef::from(self.to_ref()).block_hash()
    }

    pub fn block_number(&self) -> u64 {
        ExecutionPayloadRef::from(self.to_ref()).block_number()
    }
}

impl<'a, T: EthSpec> From<GetPayloadResponseRef<'a, T>> for ExecutionPayloadRef<'a, T> {
    fn from(response: GetPayloadResponseRef<'a, T>) -> Self {
        map_get_payload_response_ref_into_execution_payload_ref!(&'a _, response, |inner, cons| {
            cons(&inner.execution_payload)
        })
    }
}

impl<T: EthSpec> From<GetPayloadResponse<T>> for ExecutionPayload<T> {
    fn from(response: GetPayloadResponse<T>) -> Self {
        map_get_payload_response_into_execution_payload!(response, |inner, cons| {
            cons(inner.execution_payload)
        })
    }
}

impl<T: EthSpec> From<GetPayloadResponse<T>>
    for (ExecutionPayload<T>, Uint256, Option<BlobsBundle<T>>)
{
    fn from(response: GetPayloadResponse<T>) -> Self {
        match response {
            GetPayloadResponse::Merge(inner) => (
                ExecutionPayload::Merge(inner.execution_payload),
                inner.block_value,
                None,
            ),
            GetPayloadResponse::Capella(inner) => (
                ExecutionPayload::Capella(inner.execution_payload),
                inner.block_value,
                None,
            ),
            GetPayloadResponse::Deneb(inner) => (
                ExecutionPayload::Deneb(inner.execution_payload),
                inner.block_value,
                Some(inner.blobs_bundle),
            ),
        }
    }
}

pub enum GetPayloadResponseType<E: EthSpec> {
    Full(GetPayloadResponse<E>),
    Blinded(GetPayloadResponse<E>),
}

impl<T: EthSpec> GetPayloadResponse<T> {
    pub fn execution_payload_ref(&self) -> ExecutionPayloadRef<T> {
        self.to_ref().into()
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionPayloadBodyV1<E: EthSpec> {
    pub transactions: Transactions<E>,
    pub withdrawals: Option<Withdrawals<E>>,
}

impl<E: EthSpec> ExecutionPayloadBodyV1<E> {
    pub fn to_payload(
        self,
        header: ExecutionPayloadHeader<E>,
    ) -> Result<ExecutionPayload<E>, String> {
        match header {
            ExecutionPayloadHeader::Merge(header) => {
                if self.withdrawals.is_some() {
                    return Err(format!(
                        "block {} is merge but payload body has withdrawals",
                        header.block_hash
                    ));
                }
                Ok(ExecutionPayload::Merge(ExecutionPayloadMerge {
                    parent_hash: header.parent_hash,
                    fee_recipient: header.fee_recipient,
                    state_root: header.state_root,
                    receipts_root: header.receipts_root,
                    logs_bloom: header.logs_bloom,
                    prev_randao: header.prev_randao,
                    block_number: header.block_number,
                    gas_limit: header.gas_limit,
                    gas_used: header.gas_used,
                    timestamp: header.timestamp,
                    extra_data: header.extra_data,
                    base_fee_per_gas: header.base_fee_per_gas,
                    block_hash: header.block_hash,
                    transactions: self.transactions,
                }))
            }
            ExecutionPayloadHeader::Capella(header) => {
                if let Some(withdrawals) = self.withdrawals {
                    Ok(ExecutionPayload::Capella(ExecutionPayloadCapella {
                        parent_hash: header.parent_hash,
                        fee_recipient: header.fee_recipient,
                        state_root: header.state_root,
                        receipts_root: header.receipts_root,
                        logs_bloom: header.logs_bloom,
                        prev_randao: header.prev_randao,
                        block_number: header.block_number,
                        gas_limit: header.gas_limit,
                        gas_used: header.gas_used,
                        timestamp: header.timestamp,
                        extra_data: header.extra_data,
                        base_fee_per_gas: header.base_fee_per_gas,
                        block_hash: header.block_hash,
                        transactions: self.transactions,
                        withdrawals,
                    }))
                } else {
                    Err(format!(
                        "block {} is capella but payload body doesn't have withdrawals",
                        header.block_hash
                    ))
                }
            }
            ExecutionPayloadHeader::Deneb(header) => {
                if let Some(withdrawals) = self.withdrawals {
                    Ok(ExecutionPayload::Deneb(ExecutionPayloadDeneb {
                        parent_hash: header.parent_hash,
                        fee_recipient: header.fee_recipient,
                        state_root: header.state_root,
                        receipts_root: header.receipts_root,
                        logs_bloom: header.logs_bloom,
                        prev_randao: header.prev_randao,
                        block_number: header.block_number,
                        gas_limit: header.gas_limit,
                        gas_used: header.gas_used,
                        timestamp: header.timestamp,
                        extra_data: header.extra_data,
                        base_fee_per_gas: header.base_fee_per_gas,
                        block_hash: header.block_hash,
                        transactions: self.transactions,
                        withdrawals,
                        blob_gas_used: header.blob_gas_used,
                        excess_blob_gas: header.excess_blob_gas,
                    }))
                } else {
                    Err(format!(
                        "block {} is post capella but payload body doesn't have withdrawals",
                        header.block_hash
                    ))
                }
            }
        }
    }
}

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[derive(Clone, Debug, PartialEq)]
pub struct NewPayloadRequest<E: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadMerge<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Deneb))]
    pub versioned_hashes: Vec<VersionedHash>,
    #[superstruct(only(Deneb))]
    pub parent_beacon_block_root: Hash256,
}

impl<E: EthSpec> NewPayloadRequest<E> {
    pub fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload.parent_hash,
            Self::Capella(payload) => payload.execution_payload.parent_hash,
            Self::Deneb(payload) => payload.execution_payload.parent_hash,
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload.block_hash,
            Self::Capella(payload) => payload.execution_payload.block_hash,
            Self::Deneb(payload) => payload.execution_payload.block_hash,
        }
    }

    pub fn block_number(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload.block_number,
            Self::Capella(payload) => payload.execution_payload.block_number,
            Self::Deneb(payload) => payload.execution_payload.block_number,
        }
    }

    pub fn into_execution_payload(self) -> ExecutionPayload<E> {
        map_new_payload_request_into_execution_payload!(self, |request, cons| {
            cons(request.execution_payload)
        })
    }
}

impl<'a, E: EthSpec> TryFrom<BeaconBlockRef<'a, E>> for NewPayloadRequest<E> {
    type Error = BeaconStateError;

    fn try_from(block: BeaconBlockRef<'a, E>) -> Result<Self, Self::Error> {
        match block {
            BeaconBlockRef::Base(_) | BeaconBlockRef::Altair(_) => {
                Err(Self::Error::IncorrectStateVariant)
            }
            BeaconBlockRef::Merge(block_ref) => Ok(Self::Merge(NewPayloadRequestMerge {
                execution_payload: block_ref.body.execution_payload.execution_payload.clone(),
            })),
            BeaconBlockRef::Capella(block_ref) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: block_ref.body.execution_payload.execution_payload.clone(),
            })),
            BeaconBlockRef::Deneb(block_ref) => Ok(Self::Deneb(NewPayloadRequestDeneb {
                execution_payload: block_ref.body.execution_payload.execution_payload.clone(),
                versioned_hashes: block_ref
                    .body
                    .blob_kzg_commitments
                    .iter()
                    .map(kzg_commitment_to_versioned_hash)
                    .collect(),
                parent_beacon_block_root: block_ref.parent_root,
            })),
        }
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayload<E>> for NewPayloadRequest<E> {
    type Error = BeaconStateError;

    fn try_from(payload: ExecutionPayload<E>) -> Result<Self, Self::Error> {
        match payload {
            ExecutionPayload::Merge(payload) => Ok(Self::Merge(NewPayloadRequestMerge {
                execution_payload: payload,
            })),
            ExecutionPayload::Capella(payload) => Ok(Self::Capella(NewPayloadRequestCapella {
                execution_payload: payload,
            })),
            ExecutionPayload::Deneb(_) => Err(Self::Error::IncorrectStateVariant),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EngineCapabilities {
    pub new_payload_v1: bool,
    pub new_payload_v2: bool,
    pub new_payload_v3: bool,
    pub forkchoice_updated_v1: bool,
    pub forkchoice_updated_v2: bool,
    pub forkchoice_updated_v3: bool,
    pub get_payload_bodies_by_hash_v1: bool,
    pub get_payload_bodies_by_range_v1: bool,
    pub get_payload_v1: bool,
    pub get_payload_v2: bool,
    pub get_payload_v3: bool,
}

impl EngineCapabilities {
    pub fn to_response(&self) -> Vec<&str> {
        let mut response = Vec::new();
        if self.new_payload_v1 {
            response.push(ENGINE_NEW_PAYLOAD_V1);
        }
        if self.new_payload_v2 {
            response.push(ENGINE_NEW_PAYLOAD_V2);
        }
        if self.new_payload_v3 {
            response.push(ENGINE_NEW_PAYLOAD_V3);
        }
        if self.forkchoice_updated_v1 {
            response.push(ENGINE_FORKCHOICE_UPDATED_V1);
        }
        if self.forkchoice_updated_v2 {
            response.push(ENGINE_FORKCHOICE_UPDATED_V2);
        }
        if self.forkchoice_updated_v3 {
            response.push(ENGINE_FORKCHOICE_UPDATED_V3);
        }
        if self.get_payload_bodies_by_hash_v1 {
            response.push(ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1);
        }
        if self.get_payload_bodies_by_range_v1 {
            response.push(ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1);
        }
        if self.get_payload_v1 {
            response.push(ENGINE_GET_PAYLOAD_V1);
        }
        if self.get_payload_v2 {
            response.push(ENGINE_GET_PAYLOAD_V2);
        }
        if self.get_payload_v3 {
            response.push(ENGINE_GET_PAYLOAD_V3);
        }

        response
    }
}

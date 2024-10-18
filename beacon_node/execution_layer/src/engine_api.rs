use crate::engines::ForkchoiceState;
use crate::http::{
    ENGINE_FORKCHOICE_UPDATED_V1, ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_FORKCHOICE_UPDATED_V3,
    ENGINE_GET_BLOBS_V1, ENGINE_GET_CLIENT_VERSION_V1, ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1,
    ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1, ENGINE_GET_PAYLOAD_V1, ENGINE_GET_PAYLOAD_V2,
    ENGINE_GET_PAYLOAD_V3, ENGINE_GET_PAYLOAD_V4, ENGINE_NEW_PAYLOAD_V1, ENGINE_NEW_PAYLOAD_V2,
    ENGINE_NEW_PAYLOAD_V3, ENGINE_NEW_PAYLOAD_V4,
};
use eth2::types::{
    BlobsBundle, SsePayloadAttributes, SsePayloadAttributesV1, SsePayloadAttributesV2,
    SsePayloadAttributesV3,
};
use http::deposit_methods::RpcError;
pub use json_structures::{JsonWithdrawal, TransitionConfigurationV1};
use pretty_reqwest_error::PrettyReqwestError;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use strum::IntoStaticStr;
use superstruct::superstruct;
pub use types::{
    Address, BeaconBlockRef, ConsolidationRequest, EthSpec, ExecutionBlockHash, ExecutionPayload,
    ExecutionPayloadHeader, ExecutionPayloadRef, FixedVector, ForkName, Hash256, Transactions,
    Uint256, VariableList, Withdrawal, Withdrawals,
};
use types::{
    ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
    ExecutionPayloadElectra, ExecutionRequests, KzgProofs,
};
use types::{Graffiti, GRAFFITI_BYTES_LEN};

pub mod auth;
pub mod http;
pub mod json_structures;
mod new_payload_request;

pub use new_payload_request::{
    NewPayloadRequest, NewPayloadRequestBellatrix, NewPayloadRequestCapella,
    NewPayloadRequestDeneb, NewPayloadRequestElectra,
};

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
    SszError(ssz_types::Error),
    DeserializeWithdrawals(ssz_types::Error),
    DeserializeDepositRequests(ssz_types::Error),
    DeserializeWithdrawalRequests(ssz_types::Error),
    BuilderApi(builder_client::Error),
    IncorrectStateVariant,
    RequiredMethodUnsupported(&'static str),
    UnsupportedForkVariant(String),
    InvalidClientVersion(String),
    TooManyConsolidationRequests(usize),
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
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(derive(Clone, Debug, PartialEq),),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct GetPayloadResponse<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra<E>,
    pub block_value: Uint256,
    #[superstruct(only(Deneb, Electra))]
    pub blobs_bundle: BlobsBundle<E>,
    #[superstruct(only(Deneb, Electra), partial_getter(copy))]
    pub should_override_builder: bool,
    #[superstruct(only(Electra))]
    pub requests: ExecutionRequests<E>,
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

impl<'a, E: EthSpec> From<GetPayloadResponseRef<'a, E>> for ExecutionPayloadRef<'a, E> {
    fn from(response: GetPayloadResponseRef<'a, E>) -> Self {
        map_get_payload_response_ref_into_execution_payload_ref!(&'a _, response, |inner, cons| {
            cons(&inner.execution_payload)
        })
    }
}

impl<E: EthSpec> From<GetPayloadResponse<E>> for ExecutionPayload<E> {
    fn from(response: GetPayloadResponse<E>) -> Self {
        map_get_payload_response_into_execution_payload!(response, |inner, cons| {
            cons(inner.execution_payload)
        })
    }
}

impl<E: EthSpec> From<GetPayloadResponse<E>>
    for (
        ExecutionPayload<E>,
        Uint256,
        Option<BlobsBundle<E>>,
        Option<ExecutionRequests<E>>,
    )
{
    fn from(response: GetPayloadResponse<E>) -> Self {
        match response {
            GetPayloadResponse::Bellatrix(inner) => (
                ExecutionPayload::Bellatrix(inner.execution_payload),
                inner.block_value,
                None,
                None,
            ),
            GetPayloadResponse::Capella(inner) => (
                ExecutionPayload::Capella(inner.execution_payload),
                inner.block_value,
                None,
                None,
            ),
            GetPayloadResponse::Deneb(inner) => (
                ExecutionPayload::Deneb(inner.execution_payload),
                inner.block_value,
                Some(inner.blobs_bundle),
                None,
            ),
            GetPayloadResponse::Electra(inner) => (
                ExecutionPayload::Electra(inner.execution_payload),
                inner.block_value,
                Some(inner.blobs_bundle),
                Some(inner.requests),
            ),
        }
    }
}

pub enum GetPayloadResponseType<E: EthSpec> {
    Full(GetPayloadResponse<E>),
    Blinded(GetPayloadResponse<E>),
}

impl<E: EthSpec> GetPayloadResponse<E> {
    pub fn execution_payload_ref(&self) -> ExecutionPayloadRef<E> {
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
            ExecutionPayloadHeader::Bellatrix(header) => {
                if self.withdrawals.is_some() {
                    return Err(format!(
                        "block {} is bellatrix but payload body has withdrawals",
                        header.block_hash
                    ));
                }
                Ok(ExecutionPayload::Bellatrix(ExecutionPayloadBellatrix {
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
            ExecutionPayloadHeader::Electra(header) => {
                if let Some(withdrawals) = self.withdrawals {
                    Ok(ExecutionPayload::Electra(ExecutionPayloadElectra {
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

#[derive(Clone, Copy, Debug)]
pub struct EngineCapabilities {
    pub new_payload_v1: bool,
    pub new_payload_v2: bool,
    pub new_payload_v3: bool,
    pub new_payload_v4: bool,
    pub forkchoice_updated_v1: bool,
    pub forkchoice_updated_v2: bool,
    pub forkchoice_updated_v3: bool,
    pub get_payload_bodies_by_hash_v1: bool,
    pub get_payload_bodies_by_range_v1: bool,
    pub get_payload_v1: bool,
    pub get_payload_v2: bool,
    pub get_payload_v3: bool,
    pub get_payload_v4: bool,
    pub get_client_version_v1: bool,
    pub get_blobs_v1: bool,
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
        if self.new_payload_v4 {
            response.push(ENGINE_NEW_PAYLOAD_V4);
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
        if self.get_payload_v4 {
            response.push(ENGINE_GET_PAYLOAD_V4);
        }
        if self.get_client_version_v1 {
            response.push(ENGINE_GET_CLIENT_VERSION_V1);
        }
        if self.get_blobs_v1 {
            response.push(ENGINE_GET_BLOBS_V1);
        }

        response
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClientCode {
    Besu,
    EtherumJS,
    Erigon,
    GoEthereum,
    Grandine,
    Lighthouse,
    Lodestar,
    Nethermind,
    Nimbus,
    TrinExecution,
    Teku,
    Prysm,
    Reth,
    Unknown(String),
}

impl std::fmt::Display for ClientCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ClientCode::Besu => "BU",
            ClientCode::EtherumJS => "EJ",
            ClientCode::Erigon => "EG",
            ClientCode::GoEthereum => "GE",
            ClientCode::Grandine => "GR",
            ClientCode::Lighthouse => "LH",
            ClientCode::Lodestar => "LS",
            ClientCode::Nethermind => "NM",
            ClientCode::Nimbus => "NB",
            ClientCode::TrinExecution => "TE",
            ClientCode::Teku => "TK",
            ClientCode::Prysm => "PM",
            ClientCode::Reth => "RH",
            ClientCode::Unknown(code) => code,
        };
        write!(f, "{}", s)
    }
}

impl TryFrom<String> for ClientCode {
    type Error = String;

    fn try_from(code: String) -> Result<Self, Self::Error> {
        match code.as_str() {
            "BU" => Ok(Self::Besu),
            "EJ" => Ok(Self::EtherumJS),
            "EG" => Ok(Self::Erigon),
            "GE" => Ok(Self::GoEthereum),
            "GR" => Ok(Self::Grandine),
            "LH" => Ok(Self::Lighthouse),
            "LS" => Ok(Self::Lodestar),
            "NM" => Ok(Self::Nethermind),
            "NB" => Ok(Self::Nimbus),
            "TE" => Ok(Self::TrinExecution),
            "TK" => Ok(Self::Teku),
            "PM" => Ok(Self::Prysm),
            "RH" => Ok(Self::Reth),
            string => {
                if string.len() == 2 {
                    Ok(Self::Unknown(code))
                } else {
                    Err(format!("Invalid client code: {}", code))
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommitPrefix(pub String);

impl TryFrom<String> for CommitPrefix {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Check if the input starts with '0x' and strip it if it does
        let commit_prefix = value.strip_prefix("0x").unwrap_or(&value);

        // Ensure length is exactly 8 characters after '0x' removal
        if commit_prefix.len() != 8 {
            return Err(
                "Input must be exactly 8 characters long (excluding any '0x' prefix)".to_string(),
            );
        }

        // Ensure all characters are valid hex digits
        if commit_prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(CommitPrefix(commit_prefix.to_lowercase()))
        } else {
            Err("Input must contain only hexadecimal characters".to_string())
        }
    }
}

impl std::fmt::Display for CommitPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug)]
pub struct ClientVersionV1 {
    pub code: ClientCode,
    pub name: String,
    pub version: String,
    pub commit: CommitPrefix,
}

impl ClientVersionV1 {
    pub fn calculate_graffiti(&self, lighthouse_commit_prefix: CommitPrefix) -> Graffiti {
        let graffiti_string = format!(
            "{}{}LH{}",
            self.code,
            self.commit
                .0
                .get(..4)
                .map_or_else(|| self.commit.0.as_str(), |s| s)
                .to_lowercase(),
            lighthouse_commit_prefix
                .0
                .get(..4)
                .unwrap_or("0000")
                .to_lowercase(),
        );
        let mut graffiti_bytes = [0u8; GRAFFITI_BYTES_LEN];
        let bytes_to_copy = std::cmp::min(graffiti_string.len(), GRAFFITI_BYTES_LEN);
        graffiti_bytes[..bytes_to_copy]
            .copy_from_slice(&graffiti_string.as_bytes()[..bytes_to_copy]);

        Graffiti::from(graffiti_bytes)
    }
}

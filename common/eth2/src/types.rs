//! This module exposes a superset of the `types` crate. It adds additional types that are only
//! required for the HTTP API.

use crate::{
    Error as ServerError, CONSENSUS_BLOCK_VALUE_HEADER, CONSENSUS_VERSION_HEADER,
    EXECUTION_PAYLOAD_BLINDED_HEADER, EXECUTION_PAYLOAD_VALUE_HEADER,
};
use lighthouse_network::{ConnectionDirection, Enr, Multiaddr, PeerConnectionStatus};
use mediatype::{names, MediaType, MediaTypeList};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use std::fmt::{self, Display};
use std::str::{from_utf8, FromStr};
use std::sync::Arc;
use std::time::Duration;
use types::beacon_block_body::KzgCommitments;
pub use types::*;

#[cfg(feature = "lighthouse")]
use crate::lighthouse::BlockReward;

/// An API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Error {
    Indexed(IndexedErrorMessage),
    Message(ErrorMessage),
}

/// An API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
    #[serde(default)]
    pub stacktraces: Vec<String>,
}

/// An indexed API error serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexedErrorMessage {
    pub code: u16,
    pub message: String,
    pub failures: Vec<Failure>,
}

/// A single failure in an index of API errors, serializable to JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Failure {
    pub index: u64,
    pub message: String,
}

impl Failure {
    pub fn new(index: usize, message: String) -> Self {
        Self {
            index: index as u64,
            message,
        }
    }
}

/// The version of a single API endpoint, e.g. the `v1` in `/eth/v1/beacon/blocks`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EndpointVersion(pub u64);

impl FromStr for EndpointVersion {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(version_str) = s.strip_prefix('v') {
            u64::from_str(version_str)
                .map(EndpointVersion)
                .map_err(|_| ())
        } else {
            Err(())
        }
    }
}

impl std::fmt::Display for EndpointVersion {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "v{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenesisData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub genesis_time: u64,
    pub genesis_validators_root: Hash256,
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub genesis_fork_version: [u8; 4],
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BlockId {
    Head,
    Genesis,
    Finalized,
    Justified,
    Slot(Slot),
    Root(Hash256),
}

impl FromStr for BlockId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "head" => Ok(BlockId::Head),
            "genesis" => Ok(BlockId::Genesis),
            "finalized" => Ok(BlockId::Finalized),
            "justified" => Ok(BlockId::Justified),
            other => {
                if other.starts_with("0x") {
                    Hash256::from_str(&s[2..])
                        .map(BlockId::Root)
                        .map_err(|e| format!("{} cannot be parsed as a root", e))
                } else {
                    u64::from_str(s)
                        .map(Slot::new)
                        .map(BlockId::Slot)
                        .map_err(|_| format!("{} cannot be parsed as a parameter", s))
                }
            }
        }
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockId::Head => write!(f, "head"),
            BlockId::Genesis => write!(f, "genesis"),
            BlockId::Finalized => write!(f, "finalized"),
            BlockId::Justified => write!(f, "justified"),
            BlockId::Slot(slot) => write!(f, "{}", slot),
            BlockId::Root(root) => write!(f, "{:?}", root),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum StateId {
    Head,
    Genesis,
    Finalized,
    Justified,
    Slot(Slot),
    Root(Hash256),
}

impl FromStr for StateId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "head" => Ok(StateId::Head),
            "genesis" => Ok(StateId::Genesis),
            "finalized" => Ok(StateId::Finalized),
            "justified" => Ok(StateId::Justified),
            other => {
                if other.starts_with("0x") {
                    Hash256::from_str(&s[2..])
                        .map(StateId::Root)
                        .map_err(|e| format!("{} cannot be parsed as a root", e))
                } else {
                    u64::from_str(s)
                        .map(Slot::new)
                        .map(StateId::Slot)
                        .map_err(|_| format!("{} cannot be parsed as a slot", s))
                }
            }
        }
    }
}

impl fmt::Display for StateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateId::Head => write!(f, "head"),
            StateId::Genesis => write!(f, "genesis"),
            StateId::Finalized => write!(f, "finalized"),
            StateId::Justified => write!(f, "justified"),
            StateId::Slot(slot) => write!(f, "{}", slot),
            StateId::Root(root) => write!(f, "{:?}", root),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + serde::de::DeserializeOwned")]
pub struct DutiesResponse<T: Serialize + serde::de::DeserializeOwned> {
    pub dependent_root: Hash256,
    pub execution_optimistic: Option<bool>,
    pub data: T,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + serde::de::DeserializeOwned")]
pub struct ExecutionOptimisticResponse<T: Serialize + serde::de::DeserializeOwned> {
    pub execution_optimistic: Option<bool>,
    pub data: T,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + serde::de::DeserializeOwned")]
pub struct ExecutionOptimisticFinalizedResponse<T: Serialize + serde::de::DeserializeOwned> {
    pub execution_optimistic: Option<bool>,
    pub finalized: Option<bool>,
    pub data: T,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + serde::de::DeserializeOwned")]
pub struct GenericResponse<T: Serialize + serde::de::DeserializeOwned> {
    pub data: T,
}

impl<T: Serialize + serde::de::DeserializeOwned> From<T> for GenericResponse<T> {
    fn from(data: T) -> Self {
        Self { data }
    }
}

impl<T: Serialize + serde::de::DeserializeOwned> GenericResponse<T> {
    pub fn add_execution_optimistic(
        self,
        execution_optimistic: bool,
    ) -> ExecutionOptimisticResponse<T> {
        ExecutionOptimisticResponse {
            execution_optimistic: Some(execution_optimistic),
            data: self.data,
        }
    }

    pub fn add_execution_optimistic_finalized(
        self,
        execution_optimistic: bool,
        finalized: bool,
    ) -> ExecutionOptimisticFinalizedResponse<T> {
        ExecutionOptimisticFinalizedResponse {
            execution_optimistic: Some(execution_optimistic),
            finalized: Some(finalized),
            data: self.data,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
#[serde(bound = "T: Serialize")]
pub struct GenericResponseRef<'a, T: Serialize> {
    pub data: &'a T,
}

impl<'a, T: Serialize> From<&'a T> for GenericResponseRef<'a, T> {
    fn from(data: &'a T) -> Self {
        Self { data }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RootData {
    pub root: Hash256,
}

impl From<Hash256> for RootData {
    fn from(root: Hash256) -> Self {
        Self { root }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalityCheckpointsData {
    pub previous_justified: Checkpoint,
    pub current_justified: Checkpoint,
    pub finalized: Checkpoint,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(into = "String")]
#[serde(try_from = "std::borrow::Cow<str>")]
pub enum ValidatorId {
    PublicKey(PublicKeyBytes),
    Index(u64),
}

impl TryFrom<std::borrow::Cow<'_, str>> for ValidatorId {
    type Error = String;

    fn try_from(s: std::borrow::Cow<str>) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl FromStr for ValidatorId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("0x") {
            PublicKeyBytes::from_str(s)
                .map(ValidatorId::PublicKey)
                .map_err(|e| format!("{} cannot be parsed as a public key: {}", s, e))
        } else {
            u64::from_str(s)
                .map(ValidatorId::Index)
                .map_err(|e| format!("{} cannot be parsed as a slot: {}", s, e))
        }
    }
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidatorId::PublicKey(pubkey) => write!(f, "{:?}", pubkey),
            ValidatorId::Index(index) => write!(f, "{}", index),
        }
    }
}

impl From<ValidatorId> for String {
    fn from(id: ValidatorId) -> String {
        id.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub balance: u64,
    pub status: ValidatorStatus,
    pub validator: Validator,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorBalanceData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub balance: u64,
}

// Implemented according to what is described here:
//
// https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ
//
// We expect this to be updated in v2 of the standard api to
// this proposal:
//
// https://hackmd.io/bQxMDRt1RbS1TLno8K4NPg?view
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    PendingInitialized,
    PendingQueued,
    ActiveOngoing,
    ActiveExiting,
    ActiveSlashed,
    ExitedUnslashed,
    ExitedSlashed,
    WithdrawalPossible,
    WithdrawalDone,
    Active,
    Pending,
    Exited,
    Withdrawal,
}

impl ValidatorStatus {
    pub fn from_validator(validator: &Validator, epoch: Epoch, far_future_epoch: Epoch) -> Self {
        if validator.is_withdrawable_at(epoch) {
            if validator.effective_balance == 0 {
                ValidatorStatus::WithdrawalDone
            } else {
                ValidatorStatus::WithdrawalPossible
            }
        } else if validator.is_exited_at(epoch) && epoch < validator.withdrawable_epoch {
            if validator.slashed {
                ValidatorStatus::ExitedSlashed
            } else {
                ValidatorStatus::ExitedUnslashed
            }
        } else if validator.is_active_at(epoch) {
            if validator.exit_epoch < far_future_epoch {
                if validator.slashed {
                    ValidatorStatus::ActiveSlashed
                } else {
                    ValidatorStatus::ActiveExiting
                }
            } else {
                ValidatorStatus::ActiveOngoing
            }
        // `pending` statuses are specified as validators where `validator.activation_epoch > current_epoch`.
        // If this code is reached, this criteria must have been met because `validator.is_active_at(epoch)`,
        // `validator.is_exited_at(epoch)`, and `validator.is_withdrawable_at(epoch)` all returned false.
        } else if validator.activation_eligibility_epoch == far_future_epoch {
            ValidatorStatus::PendingInitialized
        } else {
            ValidatorStatus::PendingQueued
        }
    }

    pub fn superstatus(&self) -> Self {
        match self {
            ValidatorStatus::PendingInitialized | ValidatorStatus::PendingQueued => {
                ValidatorStatus::Pending
            }
            ValidatorStatus::ActiveOngoing
            | ValidatorStatus::ActiveExiting
            | ValidatorStatus::ActiveSlashed => ValidatorStatus::Active,
            ValidatorStatus::ExitedUnslashed | ValidatorStatus::ExitedSlashed => {
                ValidatorStatus::Exited
            }
            ValidatorStatus::WithdrawalPossible | ValidatorStatus::WithdrawalDone => {
                ValidatorStatus::Withdrawal
            }
            ValidatorStatus::Active
            | ValidatorStatus::Pending
            | ValidatorStatus::Exited
            | ValidatorStatus::Withdrawal => *self,
        }
    }
}

impl FromStr for ValidatorStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending_initialized" => Ok(ValidatorStatus::PendingInitialized),
            "pending_queued" => Ok(ValidatorStatus::PendingQueued),
            "active_ongoing" => Ok(ValidatorStatus::ActiveOngoing),
            "active_exiting" => Ok(ValidatorStatus::ActiveExiting),
            "active_slashed" => Ok(ValidatorStatus::ActiveSlashed),
            "exited_unslashed" => Ok(ValidatorStatus::ExitedUnslashed),
            "exited_slashed" => Ok(ValidatorStatus::ExitedSlashed),
            "withdrawal_possible" => Ok(ValidatorStatus::WithdrawalPossible),
            "withdrawal_done" => Ok(ValidatorStatus::WithdrawalDone),
            "active" => Ok(ValidatorStatus::Active),
            "pending" => Ok(ValidatorStatus::Pending),
            "exited" => Ok(ValidatorStatus::Exited),
            "withdrawal" => Ok(ValidatorStatus::Withdrawal),
            _ => Err(format!("{} cannot be parsed as a validator status.", s)),
        }
    }
}

impl fmt::Display for ValidatorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidatorStatus::PendingInitialized => write!(f, "pending_initialized"),
            ValidatorStatus::PendingQueued => write!(f, "pending_queued"),
            ValidatorStatus::ActiveOngoing => write!(f, "active_ongoing"),
            ValidatorStatus::ActiveExiting => write!(f, "active_exiting"),
            ValidatorStatus::ActiveSlashed => write!(f, "active_slashed"),
            ValidatorStatus::ExitedUnslashed => write!(f, "exited_unslashed"),
            ValidatorStatus::ExitedSlashed => write!(f, "exited_slashed"),
            ValidatorStatus::WithdrawalPossible => write!(f, "withdrawal_possible"),
            ValidatorStatus::WithdrawalDone => write!(f, "withdrawal_done"),
            ValidatorStatus::Active => write!(f, "active"),
            ValidatorStatus::Pending => write!(f, "pending"),
            ValidatorStatus::Exited => write!(f, "exited"),
            ValidatorStatus::Withdrawal => write!(f, "withdrawal"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CommitteesQuery {
    pub slot: Option<Slot>,
    pub index: Option<u64>,
    pub epoch: Option<Epoch>,
}

#[derive(Serialize, Deserialize)]
pub struct SyncCommitteesQuery {
    pub epoch: Option<Epoch>,
}

#[derive(Serialize, Deserialize)]
pub struct RandaoQuery {
    pub epoch: Option<Epoch>,
}

#[derive(Serialize, Deserialize)]
pub struct AttestationPoolQuery {
    pub slot: Option<Slot>,
    pub committee_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorsQuery {
    #[serde(default, deserialize_with = "option_query_vec")]
    pub id: Option<Vec<ValidatorId>>,
    #[serde(default, deserialize_with = "option_query_vec")]
    pub status: Option<Vec<ValidatorStatus>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorsRequestBody {
    #[serde(default)]
    pub ids: Option<Vec<ValidatorId>>,
    #[serde(default)]
    pub statuses: Option<Vec<ValidatorStatus>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitteeData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validators: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncCommitteeByValidatorIndices {
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub validators: Vec<u64>,
    pub validator_aggregates: Vec<SyncSubcommittee>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RandaoMix {
    pub randao: Hash256,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyncSubcommittee {
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub indices: Vec<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct HeadersQuery {
    pub slot: Option<Slot>,
    pub parent_root: Option<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeaderAndSignature {
    pub message: BeaconBlockHeader,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeaderData {
    pub root: Hash256,
    pub canonical: bool,
    pub header: BlockHeaderAndSignature,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepositContractData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub chain_id: u64,
    #[serde(with = "serde_utils::address_hex")]
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainHeadData {
    pub slot: Slot,
    pub root: Hash256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_optimistic: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityData {
    pub peer_id: String,
    pub enr: Enr,
    pub p2p_addresses: Vec<Multiaddr>,
    pub discovery_addresses: Vec<Multiaddr>,
    pub metadata: MetaData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub seq_number: u64,
    pub attnets: String,
    pub syncnets: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionData {
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncingData {
    pub is_syncing: bool,
    pub is_optimistic: bool,
    pub el_offline: bool,
    pub head_slot: Slot,
    pub sync_distance: Slot,
}

#[derive(Serialize, Deserialize)]
pub struct ExpectedWithdrawalsQuery {
    pub proposal_slot: Option<Slot>,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
#[serde(try_from = "String", bound = "T: FromStr")]
pub struct QueryVec<T: FromStr> {
    values: Vec<T>,
}

fn query_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
{
    let vec: Vec<QueryVec<T>> = Deserialize::deserialize(deserializer)?;
    Ok(Vec::from(QueryVec::from(vec)))
}

fn option_query_vec<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
{
    let vec: Vec<QueryVec<T>> = Deserialize::deserialize(deserializer)?;
    if vec.is_empty() {
        return Ok(None);
    }

    Ok(Some(Vec::from(QueryVec::from(vec))))
}

impl<T: FromStr> From<Vec<QueryVec<T>>> for QueryVec<T> {
    fn from(vecs: Vec<QueryVec<T>>) -> Self {
        Self {
            values: vecs.into_iter().flat_map(|qv| qv.values).collect(),
        }
    }
}

impl<T: FromStr> TryFrom<String> for QueryVec<T> {
    type Error = String;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        if string.is_empty() {
            return Ok(Self { values: vec![] });
        }

        Ok(Self {
            values: string
                .split(',')
                .map(|s| s.parse().map_err(|_| "unable to parse query".to_string()))
                .collect::<Result<Vec<T>, String>>()?,
        })
    }
}

impl<T: FromStr> From<QueryVec<T>> for Vec<T> {
    fn from(vec: QueryVec<T>) -> Vec<T> {
        vec.values
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorBalancesQuery {
    #[serde(default, deserialize_with = "option_query_vec")]
    pub id: Option<Vec<ValidatorId>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidatorBalancesRequestBody {
    pub ids: Vec<ValidatorId>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobIndicesQuery {
    #[serde(default, deserialize_with = "option_query_vec")]
    pub indices: Option<Vec<u64>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidatorIndexData(#[serde(with = "serde_utils::quoted_u64_vec")] pub Vec<u64>);

/// Borrowed variant of `ValidatorIndexData`, for serializing/sending.
#[derive(Clone, Copy, Serialize)]
#[serde(transparent)]
pub struct ValidatorIndexDataRef<'a>(
    #[serde(serialize_with = "serde_utils::quoted_u64_vec::serialize")] pub &'a [u64],
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttesterData {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committees_at_slot: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: CommitteeIndex,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_length: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_committee_index: u64,
    pub slot: Slot,
}

impl AttesterData {
    pub fn match_attestation_data<E: EthSpec>(
        &self,
        attestation_data: &AttestationData,
        spec: &ChainSpec,
    ) -> bool {
        if spec.fork_name_at_slot::<E>(attestation_data.slot) < ForkName::Electra {
            self.slot == attestation_data.slot && self.committee_index == attestation_data.index
        } else {
            // After electra `attestation_data.index` is set to 0 and does not match the duties
            self.slot == attestation_data.slot
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposerData {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub slot: Slot,
}

#[derive(Clone, Deserialize)]
pub struct ValidatorBlocksQuery {
    pub randao_reveal: SignatureBytes,
    pub graffiti: Option<Graffiti>,
    pub skip_randao_verification: SkipRandaoVerification,
    pub builder_boost_factor: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Option<String>")]
pub enum SkipRandaoVerification {
    Yes,
    #[default]
    No,
}

/// Parse a `skip_randao_verification` query parameter.
impl TryFrom<Option<String>> for SkipRandaoVerification {
    type Error = String;

    fn try_from(opt: Option<String>) -> Result<Self, String> {
        match opt.as_deref() {
            None => Ok(SkipRandaoVerification::No),
            Some("") => Ok(SkipRandaoVerification::Yes),
            Some(s) => Err(format!(
                "skip_randao_verification does not take a value, got: {s}"
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorAttestationDataQuery {
    pub slot: Slot,
    pub committee_index: CommitteeIndex,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorAggregateAttestationQuery {
    pub attestation_data_root: Hash256,
    pub slot: Slot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committee_index: Option<CommitteeIndex>,
}

#[derive(Clone, Deserialize)]
pub struct LightClientUpdatesQuery {
    pub start_period: u64,
    pub count: u64,
}

#[derive(Encode, Decode)]
pub struct LightClientUpdateSszResponse {
    pub response_chunk_len: Vec<u8>,
    pub response_chunk: Vec<u8>,
}

#[derive(Encode, Decode)]
pub struct LightClientUpdateResponseChunk {
    pub context: [u8; 4],
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BeaconCommitteeSubscription {
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committee_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub committees_at_slot: u64,
    pub slot: Slot,
    pub is_aggregator: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeersQuery {
    #[serde(default, deserialize_with = "option_query_vec")]
    pub state: Option<Vec<PeerState>>,
    #[serde(default, deserialize_with = "option_query_vec")]
    pub direction: Option<Vec<PeerDirection>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerData {
    pub peer_id: String,
    pub enr: Option<String>,
    pub last_seen_p2p_address: String,
    pub state: PeerState,
    pub direction: PeerDirection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeersData {
    pub data: Vec<PeerData>,
    pub meta: PeersMetaData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeersMetaData {
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerState {
    Connected,
    Connecting,
    Disconnected,
    Disconnecting,
}

impl PeerState {
    pub fn from_peer_connection_status(status: &PeerConnectionStatus) -> Self {
        match status {
            PeerConnectionStatus::Connected { .. } => PeerState::Connected,
            PeerConnectionStatus::Dialing { .. } => PeerState::Connecting,
            PeerConnectionStatus::Disconnecting { .. } => PeerState::Disconnecting,
            PeerConnectionStatus::Disconnected { .. }
            | PeerConnectionStatus::Banned { .. }
            | PeerConnectionStatus::Unknown => PeerState::Disconnected,
        }
    }
}

impl FromStr for PeerState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "connected" => Ok(PeerState::Connected),
            "connecting" => Ok(PeerState::Connecting),
            "disconnected" => Ok(PeerState::Disconnected),
            "disconnecting" => Ok(PeerState::Disconnecting),
            _ => Err("peer state cannot be parsed.".to_string()),
        }
    }
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerState::Connected => write!(f, "connected"),
            PeerState::Connecting => write!(f, "connecting"),
            PeerState::Disconnected => write!(f, "disconnected"),
            PeerState::Disconnecting => write!(f, "disconnecting"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

impl PeerDirection {
    pub fn from_connection_direction(direction: &ConnectionDirection) -> Self {
        match direction {
            ConnectionDirection::Incoming => PeerDirection::Inbound,
            ConnectionDirection::Outgoing => PeerDirection::Outbound,
        }
    }
}

impl FromStr for PeerDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "inbound" => Ok(PeerDirection::Inbound),
            "outbound" => Ok(PeerDirection::Outbound),
            _ => Err("peer direction cannot be parsed.".to_string()),
        }
    }
}

impl fmt::Display for PeerDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerDirection::Inbound => write!(f, "inbound"),
            PeerDirection::Outbound => write!(f, "outbound"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerCount {
    #[serde(with = "serde_utils::quoted_u64")]
    pub connected: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub connecting: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub disconnected: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub disconnecting: u64,
}

// --------- Server Sent Event Types -----------

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseBlock {
    pub slot: Slot,
    pub block: Hash256,
    pub execution_optimistic: bool,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseBlobSidecar {
    pub block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub kzg_commitment: KzgCommitment,
    pub versioned_hash: VersionedHash,
}

impl SseBlobSidecar {
    pub fn from_blob_sidecar<E: EthSpec>(blob_sidecar: &BlobSidecar<E>) -> SseBlobSidecar {
        SseBlobSidecar {
            block_root: blob_sidecar.block_root(),
            index: blob_sidecar.index,
            slot: blob_sidecar.slot(),
            kzg_commitment: blob_sidecar.kzg_commitment,
            versioned_hash: blob_sidecar.kzg_commitment.calculate_versioned_hash(),
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseFinalizedCheckpoint {
    pub block: Hash256,
    pub state: Hash256,
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseHead {
    pub slot: Slot,
    pub block: Hash256,
    pub state: Hash256,
    pub current_duty_dependent_root: Hash256,
    pub previous_duty_dependent_root: Hash256,
    pub epoch_transition: bool,
    pub execution_optimistic: bool,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockGossip {
    pub slot: Slot,
    pub block: Hash256,
}
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseChainReorg {
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub depth: u64,
    pub old_head_block: Hash256,
    pub old_head_state: Hash256,
    pub new_head_block: Hash256,
    pub new_head_state: Hash256,
    pub epoch: Epoch,
    pub execution_optimistic: bool,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct SseLateHead {
    pub slot: Slot,
    pub block: Hash256,
    pub proposer_index: u64,
    pub peer_id: Option<String>,
    pub peer_client: Option<String>,
    pub proposer_graffiti: String,
    pub block_delay: Duration,
    pub observed_delay: Option<Duration>,
    pub imported_delay: Option<Duration>,
    pub set_as_head_delay: Option<Duration>,
    pub execution_optimistic: bool,
}

#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize))
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub struct SsePayloadAttributes {
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub timestamp: u64,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::address_hex")]
    pub suggested_fee_recipient: Address,
    #[superstruct(only(V2, V3))]
    pub withdrawals: Vec<Withdrawal>,
    #[superstruct(only(V3), partial_getter(copy))]
    pub parent_beacon_block_root: Hash256,
}

#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct SseExtendedPayloadAttributesGeneric<T> {
    pub proposal_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub parent_block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub parent_block_number: u64,

    pub parent_block_hash: ExecutionBlockHash,
    pub payload_attributes: T,
}

pub type SseExtendedPayloadAttributes = SseExtendedPayloadAttributesGeneric<SsePayloadAttributes>;
pub type VersionedSsePayloadAttributes = ForkVersionedResponse<SseExtendedPayloadAttributes>;

impl ForkVersionDeserialize for SsePayloadAttributes {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Bellatrix => serde_json::from_value(value)
                .map(Self::V1)
                .map_err(serde::de::Error::custom),
            ForkName::Capella => serde_json::from_value(value)
                .map(Self::V2)
                .map_err(serde::de::Error::custom),
            ForkName::Deneb => serde_json::from_value(value)
                .map(Self::V3)
                .map_err(serde::de::Error::custom),
            ForkName::Electra => serde_json::from_value(value)
                .map(Self::V3)
                .map_err(serde::de::Error::custom),
            // TODO(EIP7732): check this
            ForkName::EIP7732 => serde_json::from_value(value)
                .map(Self::V3)
                .map_err(serde::de::Error::custom),
            ForkName::Base | ForkName::Altair => Err(serde::de::Error::custom(format!(
                "SsePayloadAttributes deserialization for {fork_name} not implemented"
            ))),
        }
    }
}

impl ForkVersionDeserialize for SseExtendedPayloadAttributes {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let helper: SseExtendedPayloadAttributesGeneric<serde_json::Value> =
            serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            proposal_slot: helper.proposal_slot,
            proposer_index: helper.proposer_index,
            parent_block_root: helper.parent_block_root,
            parent_block_number: helper.parent_block_number,
            parent_block_hash: helper.parent_block_hash,
            payload_attributes: SsePayloadAttributes::deserialize_by_fork::<D>(
                helper.payload_attributes,
                fork_name,
            )?,
        })
    }
}

#[derive(PartialEq, Debug, Serialize, Clone)]
#[serde(bound = "E: EthSpec", untagged)]
pub enum EventKind<E: EthSpec> {
    Attestation(Box<Attestation<E>>),
    Block(SseBlock),
    BlobSidecar(SseBlobSidecar),
    FinalizedCheckpoint(SseFinalizedCheckpoint),
    Head(SseHead),
    VoluntaryExit(SignedVoluntaryExit),
    ChainReorg(SseChainReorg),
    ContributionAndProof(Box<SignedContributionAndProof<E>>),
    LateHead(SseLateHead),
    LightClientFinalityUpdate(Box<LightClientFinalityUpdate<E>>),
    LightClientOptimisticUpdate(Box<LightClientOptimisticUpdate<E>>),
    #[cfg(feature = "lighthouse")]
    BlockReward(BlockReward),
    PayloadAttributes(VersionedSsePayloadAttributes),
    ProposerSlashing(Box<ProposerSlashing>),
    AttesterSlashing(Box<AttesterSlashing<E>>),
    BlsToExecutionChange(Box<SignedBlsToExecutionChange>),
    BlockGossip(Box<BlockGossip>),
}

impl<E: EthSpec> EventKind<E> {
    pub fn topic_name(&self) -> &str {
        match self {
            EventKind::Head(_) => "head",
            EventKind::Block(_) => "block",
            EventKind::BlobSidecar(_) => "blob_sidecar",
            EventKind::Attestation(_) => "attestation",
            EventKind::VoluntaryExit(_) => "voluntary_exit",
            EventKind::FinalizedCheckpoint(_) => "finalized_checkpoint",
            EventKind::ChainReorg(_) => "chain_reorg",
            EventKind::ContributionAndProof(_) => "contribution_and_proof",
            EventKind::PayloadAttributes(_) => "payload_attributes",
            EventKind::LateHead(_) => "late_head",
            EventKind::LightClientFinalityUpdate(_) => "light_client_finality_update",
            EventKind::LightClientOptimisticUpdate(_) => "light_client_optimistic_update",
            #[cfg(feature = "lighthouse")]
            EventKind::BlockReward(_) => "block_reward",
            EventKind::ProposerSlashing(_) => "proposer_slashing",
            EventKind::AttesterSlashing(_) => "attester_slashing",
            EventKind::BlsToExecutionChange(_) => "bls_to_execution_change",
            EventKind::BlockGossip(_) => "block_gossip",
        }
    }

    pub fn from_sse_bytes(message: &[u8]) -> Result<Self, ServerError> {
        let s = from_utf8(message)
            .map_err(|e| ServerError::InvalidServerSentEvent(format!("{:?}", e)))?;

        let mut split = s.split('\n');
        let event = split
            .next()
            .ok_or_else(|| {
                ServerError::InvalidServerSentEvent("Could not parse event tag".to_string())
            })?
            .trim_start_matches("event:");
        let data = split
            .next()
            .ok_or_else(|| {
                ServerError::InvalidServerSentEvent("Could not parse data tag".to_string())
            })?
            .trim_start_matches("data:");

        match event {
            "attestation" => Ok(EventKind::Attestation(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Attestation: {:?}", e)),
            )?)),
            "block" => Ok(EventKind::Block(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Block: {:?}", e)),
            )?)),
            "blob_sidecar" => Ok(EventKind::BlobSidecar(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Blob Sidecar: {:?}", e)),
            )?)),
            "chain_reorg" => Ok(EventKind::ChainReorg(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Chain Reorg: {:?}", e)),
            )?)),
            "finalized_checkpoint" => Ok(EventKind::FinalizedCheckpoint(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Finalized Checkpoint: {:?}", e))
                })?,
            )),
            "head" => Ok(EventKind::Head(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Head: {:?}", e)),
            )?)),
            "late_head" => Ok(EventKind::LateHead(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Late Head: {:?}", e)),
            )?)),
            "voluntary_exit" => Ok(EventKind::VoluntaryExit(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Voluntary Exit: {:?}", e))
                })?,
            )),
            "contribution_and_proof" => Ok(EventKind::ContributionAndProof(Box::new(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Contribution and Proof: {:?}", e))
                })?,
            ))),
            "payload_attributes" => Ok(EventKind::PayloadAttributes(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Payload Attributes: {:?}", e))
                })?,
            )),
            "light_client_finality_update" => Ok(EventKind::LightClientFinalityUpdate(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!(
                        "Light Client Finality Update: {:?}",
                        e
                    ))
                })?,
            )),
            "light_client_optimistic_update" => Ok(EventKind::LightClientOptimisticUpdate(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!(
                        "Light Client Optimistic Update: {:?}",
                        e
                    ))
                })?,
            )),
            #[cfg(feature = "lighthouse")]
            "block_reward" => Ok(EventKind::BlockReward(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Block Reward: {:?}", e)),
            )?)),
            "attester_slashing" => Ok(EventKind::AttesterSlashing(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Attester Slashing: {:?}", e))
                })?,
            )),
            "proposer_slashing" => Ok(EventKind::ProposerSlashing(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Proposer Slashing: {:?}", e))
                })?,
            )),
            "bls_to_execution_change" => Ok(EventKind::BlsToExecutionChange(
                serde_json::from_str(data).map_err(|e| {
                    ServerError::InvalidServerSentEvent(format!("Bls To Execution Change: {:?}", e))
                })?,
            )),
            "block_gossip" => Ok(EventKind::BlockGossip(serde_json::from_str(data).map_err(
                |e| ServerError::InvalidServerSentEvent(format!("Block Gossip: {:?}", e)),
            )?)),
            _ => Err(ServerError::InvalidServerSentEvent(
                "Could not parse event tag".to_string(),
            )),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    #[serde(deserialize_with = "query_vec")]
    pub topics: Vec<EventTopic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventTopic {
    Head,
    Block,
    BlobSidecar,
    Attestation,
    VoluntaryExit,
    FinalizedCheckpoint,
    ChainReorg,
    ContributionAndProof,
    LateHead,
    PayloadAttributes,
    LightClientFinalityUpdate,
    LightClientOptimisticUpdate,
    #[cfg(feature = "lighthouse")]
    BlockReward,
    AttesterSlashing,
    ProposerSlashing,
    BlsToExecutionChange,
    BlockGossip,
}

impl FromStr for EventTopic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "head" => Ok(EventTopic::Head),
            "block" => Ok(EventTopic::Block),
            "blob_sidecar" => Ok(EventTopic::BlobSidecar),
            "attestation" => Ok(EventTopic::Attestation),
            "voluntary_exit" => Ok(EventTopic::VoluntaryExit),
            "finalized_checkpoint" => Ok(EventTopic::FinalizedCheckpoint),
            "chain_reorg" => Ok(EventTopic::ChainReorg),
            "contribution_and_proof" => Ok(EventTopic::ContributionAndProof),
            "payload_attributes" => Ok(EventTopic::PayloadAttributes),
            "late_head" => Ok(EventTopic::LateHead),
            "light_client_finality_update" => Ok(EventTopic::LightClientFinalityUpdate),
            "light_client_optimistic_update" => Ok(EventTopic::LightClientOptimisticUpdate),
            #[cfg(feature = "lighthouse")]
            "block_reward" => Ok(EventTopic::BlockReward),
            "attester_slashing" => Ok(EventTopic::AttesterSlashing),
            "proposer_slashing" => Ok(EventTopic::ProposerSlashing),
            "bls_to_execution_change" => Ok(EventTopic::BlsToExecutionChange),
            "block_gossip" => Ok(EventTopic::BlockGossip),
            _ => Err("event topic cannot be parsed.".to_string()),
        }
    }
}

impl fmt::Display for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventTopic::Head => write!(f, "head"),
            EventTopic::Block => write!(f, "block"),
            EventTopic::BlobSidecar => write!(f, "blob_sidecar"),
            EventTopic::Attestation => write!(f, "attestation"),
            EventTopic::VoluntaryExit => write!(f, "voluntary_exit"),
            EventTopic::FinalizedCheckpoint => write!(f, "finalized_checkpoint"),
            EventTopic::ChainReorg => write!(f, "chain_reorg"),
            EventTopic::ContributionAndProof => write!(f, "contribution_and_proof"),
            EventTopic::PayloadAttributes => write!(f, "payload_attributes"),
            EventTopic::LateHead => write!(f, "late_head"),
            EventTopic::LightClientFinalityUpdate => write!(f, "light_client_finality_update"),
            EventTopic::LightClientOptimisticUpdate => write!(f, "light_client_optimistic_update"),
            #[cfg(feature = "lighthouse")]
            EventTopic::BlockReward => write!(f, "block_reward"),
            EventTopic::AttesterSlashing => write!(f, "attester_slashing"),
            EventTopic::ProposerSlashing => write!(f, "proposer_slashing"),
            EventTopic::BlsToExecutionChange => write!(f, "bls_to_execution_change"),
            EventTopic::BlockGossip => write!(f, "block_gossip"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Accept {
    Json,
    Ssz,
    Any,
}

impl fmt::Display for Accept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Accept::Ssz => write!(f, "application/octet-stream"),
            Accept::Json => write!(f, "application/json"),
            Accept::Any => write!(f, "*/*"),
        }
    }
}

impl FromStr for Accept {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let media_type_list = MediaTypeList::new(s);

        // [q-factor weighting]: https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.2
        // find the highest q-factor supported accept type
        let mut highest_q = 0_u16;
        let mut accept_type = None;

        const APPLICATION: &str = names::APPLICATION.as_str();
        const OCTET_STREAM: &str = names::OCTET_STREAM.as_str();
        const JSON: &str = names::JSON.as_str();
        const STAR: &str = names::_STAR.as_str();
        const Q: &str = names::Q.as_str();

        media_type_list.into_iter().for_each(|item| {
            if let Ok(MediaType {
                ty,
                subty,
                suffix: _,
                params,
            }) = item
            {
                let q_accept = match (ty.as_str(), subty.as_str()) {
                    (APPLICATION, OCTET_STREAM) => Some(Accept::Ssz),
                    (APPLICATION, JSON) => Some(Accept::Json),
                    (STAR, STAR) => Some(Accept::Any),
                    _ => None,
                }
                .map(|item_accept_type| {
                    let q_val = params
                        .iter()
                        .find_map(|(n, v)| match n.as_str() {
                            Q => {
                                Some((v.as_str().parse::<f32>().unwrap_or(0_f32) * 1000_f32) as u16)
                            }
                            _ => None,
                        })
                        .or(Some(1000_u16));

                    (q_val.unwrap(), item_accept_type)
                });

                match q_accept {
                    Some((q, accept)) if q > highest_q => {
                        highest_q = q;
                        accept_type = Some(accept);
                    }
                    _ => (),
                }
            }
        });
        accept_type.ok_or_else(|| "accept header is not supported".to_string())
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct StandardLivenessResponseData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub is_live: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LivenessRequestData {
    pub epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub indices: Vec<u64>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct LivenessResponseData {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub epoch: Epoch,
    pub is_live: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForkChoice {
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub fork_choice_nodes: Vec<ForkChoiceNode>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkChoiceNode {
    pub slot: Slot,
    pub block_root: Hash256,
    pub parent_root: Option<Hash256>,
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub weight: u64,
    pub validity: Option<String>,
    pub execution_block_hash: Option<Hash256>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastValidation {
    Gossip,
    Consensus,
    ConsensusAndEquivocation,
}

impl Default for BroadcastValidation {
    fn default() -> Self {
        Self::Gossip
    }
}

impl Display for BroadcastValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gossip => write!(f, "gossip"),
            Self::Consensus => write!(f, "consensus"),
            Self::ConsensusAndEquivocation => write!(f, "consensus_and_equivocation"),
        }
    }
}

impl FromStr for BroadcastValidation {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gossip" => Ok(Self::Gossip),
            "consensus" => Ok(Self::Consensus),
            "consensus_and_equivocation" => Ok(Self::ConsensusAndEquivocation),
            _ => Err("Invalid broadcast validation level"),
        }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BroadcastValidationQuery {
    #[serde(default)]
    pub broadcast_validation: BroadcastValidation,
}

pub mod serde_status_code {
    use crate::StatusCode;
    use serde::{de::Error, Deserialize, Serialize};

    pub fn serialize<S>(status_code: &StatusCode, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        status_code.as_u16().serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<StatusCode, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let status_code = u16::deserialize(de)?;
        StatusCode::try_from(status_code).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Encode;

    #[test]
    fn query_vec() {
        assert_eq!(
            QueryVec::try_from("0,1,2".to_string()).unwrap(),
            QueryVec {
                values: vec![0_u64, 1, 2]
            }
        );
    }

    #[test]
    fn parse_accept_header_content() {
        assert_eq!(
            Accept::from_str("application/json; charset=utf-8").unwrap(),
            Accept::Json
        );

        assert_eq!(
            Accept::from_str("text/plain,application/octet-stream;q=0.3,application/json;q=0.9")
                .unwrap(),
            Accept::Json
        );

        assert_eq!(
            Accept::from_str("text/plain"),
            Err("accept header is not supported".to_string())
        );

        assert_eq!(
            Accept::from_str("application/json;message=\"Hello, world!\";q=0.3,*/*;q=0.6").unwrap(),
            Accept::Any
        );
    }

    #[test]
    fn ssz_signed_block_contents_pre_deneb() {
        type E = MainnetEthSpec;
        let spec = ForkName::Capella.make_genesis_spec(E::default_spec());

        let block: PublishBlockRequest<E> = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::<E>::Capella(BeaconBlockCapella::empty(&spec)),
            Signature::empty(),
        ))
        .try_into()
        .expect("should convert into signed block contents");

        let decoded: PublishBlockRequest<E> =
            PublishBlockRequest::from_ssz_bytes(&block.as_ssz_bytes(), ForkName::Capella)
                .expect("should decode Block");
        assert!(matches!(decoded, PublishBlockRequest::Block(_)));
    }

    #[test]
    fn ssz_signed_block_contents_with_blobs() {
        type E = MainnetEthSpec;
        let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());

        let block = SignedBeaconBlock::from_block(
            BeaconBlock::<E>::Deneb(BeaconBlockDeneb::empty(&spec)),
            Signature::empty(),
        );
        let blobs = BlobsList::<E>::from(vec![Blob::<E>::default()]);
        let kzg_proofs = KzgProofs::<E>::from(vec![KzgProof::empty()]);
        let signed_block_contents =
            PublishBlockRequest::new(Arc::new(block), Some((kzg_proofs, blobs)));

        let decoded: PublishBlockRequest<E> = PublishBlockRequest::from_ssz_bytes(
            &signed_block_contents.as_ssz_bytes(),
            ForkName::Deneb,
        )
        .expect("should decode BlockAndBlobSidecars");
        assert!(matches!(decoded, PublishBlockRequest::BlockContents(_)));
    }
}

#[derive(Debug, Encode, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub enum ProduceBlockV3Response<E: EthSpec> {
    Full(FullBlockContents<E>),
    Blinded(BlindedBeaconBlock<E>),
}

pub type JsonProduceBlockV3Response<E> =
    ForkVersionedResponse<ProduceBlockV3Response<E>, ProduceBlockV3Metadata>;

/// A wrapper over a [`BeaconBlock`] or a [`BlockContents`].
#[derive(Debug, Encode, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub enum FullBlockContents<E: EthSpec> {
    /// This is a full deneb variant with block and blobs.
    BlockContents(BlockContents<E>),
    /// This variant is for all pre-deneb full blocks.
    Block(BeaconBlock<E>),
}

pub type BlockContentsTuple<E> = (BeaconBlock<E>, Option<(KzgProofs<E>, BlobsList<E>)>);

// This value should never be used
fn dummy_consensus_version() -> ForkName {
    ForkName::Base
}

/// Metadata about a `ProduceBlockV3Response` which is returned in the body & headers.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProduceBlockV3Metadata {
    // The consensus version is serialized & deserialized by `ForkVersionedResponse`.
    #[serde(
        skip_serializing,
        skip_deserializing,
        default = "dummy_consensus_version"
    )]
    pub consensus_version: ForkName,
    pub execution_payload_blinded: bool,
    #[serde(with = "serde_utils::u256_dec")]
    pub execution_payload_value: Uint256,
    #[serde(with = "serde_utils::u256_dec")]
    pub consensus_block_value: Uint256,
}

impl<E: EthSpec> FullBlockContents<E> {
    pub fn new(block: BeaconBlock<E>, blob_data: Option<(KzgProofs<E>, BlobsList<E>)>) -> Self {
        match blob_data {
            Some((kzg_proofs, blobs)) => Self::BlockContents(BlockContents {
                block,
                kzg_proofs,
                blobs,
            }),
            None => Self::Block(block),
        }
    }

    /// SSZ decode with fork variant determined by slot.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        let slot_len = <Slot as Decode>::ssz_fixed_len();
        let slot_bytes = bytes
            .get(0..slot_len)
            .ok_or(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: slot_len,
            })?;
        let slot = Slot::from_ssz_bytes(slot_bytes)?;
        let fork_at_slot = spec.fork_name_at_slot::<E>(slot);
        Self::from_ssz_bytes_for_fork(bytes, fork_at_slot)
    }

    /// SSZ decode with fork variant passed in explicitly.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        if fork_name.deneb_enabled() {
            let mut builder = ssz::SszDecoderBuilder::new(bytes);

            builder.register_anonymous_variable_length_item()?;
            builder.register_type::<KzgProofs<E>>()?;
            builder.register_type::<BlobsList<E>>()?;

            let mut decoder = builder.build()?;
            let block = decoder
                .decode_next_with(|bytes| BeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name))?;
            let kzg_proofs = decoder.decode_next()?;
            let blobs = decoder.decode_next()?;

            Ok(FullBlockContents::new(block, Some((kzg_proofs, blobs))))
        } else {
            BeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name)
                .map(|block| FullBlockContents::Block(block))
        }
    }

    pub fn block(&self) -> &BeaconBlock<E> {
        match self {
            FullBlockContents::BlockContents(block_and_sidecars) => &block_and_sidecars.block,
            FullBlockContents::Block(block) => block,
        }
    }

    pub fn deconstruct(self) -> BlockContentsTuple<E> {
        match self {
            FullBlockContents::BlockContents(block_and_sidecars) => (
                block_and_sidecars.block,
                Some((block_and_sidecars.kzg_proofs, block_and_sidecars.blobs)),
            ),
            FullBlockContents::Block(block) => (block, None),
        }
    }

    /// Signs `self`, producing a `SignedBlockContents`.
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> PublishBlockRequest<E> {
        let (block, maybe_blobs) = self.deconstruct();
        let signed_block = block.sign(secret_key, fork, genesis_validators_root, spec);
        PublishBlockRequest::new(Arc::new(signed_block), maybe_blobs)
    }
}

impl<E: EthSpec> ForkVersionDeserialize for FullBlockContents<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        if fork_name.deneb_enabled() {
            Ok(FullBlockContents::BlockContents(
                BlockContents::deserialize_by_fork::<'de, D>(value, fork_name)?,
            ))
        } else {
            Ok(FullBlockContents::Block(
                BeaconBlock::deserialize_by_fork::<'de, D>(value, fork_name)?,
            ))
        }
    }
}

impl<E: EthSpec> From<FullBlockContents<E>> for BeaconBlock<E> {
    fn from(from: FullBlockContents<E>) -> BeaconBlock<E> {
        match from {
            FullBlockContents::<E>::BlockContents(block_and_sidecars) => block_and_sidecars.block,
            FullBlockContents::<E>::Block(block) => block,
        }
    }
}

pub type SignedBlockContentsTuple<E> = (
    Arc<SignedBeaconBlock<E>>,
    Option<(KzgProofs<E>, BlobsList<E>)>,
);

fn parse_required_header<T>(
    headers: &HeaderMap,
    header_name: &str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    let str_value = headers
        .get(header_name)
        .ok_or_else(|| format!("missing required header {header_name}"))?
        .to_str()
        .map_err(|e| format!("invalid value in {header_name}: {e}"))?;
    parse(str_value)
}

impl TryFrom<&HeaderMap> for ProduceBlockV3Metadata {
    type Error = String;

    fn try_from(headers: &HeaderMap) -> Result<Self, Self::Error> {
        let consensus_version = parse_required_header(headers, CONSENSUS_VERSION_HEADER, |s| {
            s.parse::<ForkName>()
                .map_err(|e| format!("invalid {CONSENSUS_VERSION_HEADER}: {e:?}"))
        })?;
        let execution_payload_blinded =
            parse_required_header(headers, EXECUTION_PAYLOAD_BLINDED_HEADER, |s| {
                s.parse::<bool>()
                    .map_err(|e| format!("invalid {EXECUTION_PAYLOAD_BLINDED_HEADER}: {e:?}"))
            })?;
        let execution_payload_value =
            parse_required_header(headers, EXECUTION_PAYLOAD_VALUE_HEADER, |s| {
                Uint256::from_str_radix(s, 10)
                    .map_err(|e| format!("invalid {EXECUTION_PAYLOAD_VALUE_HEADER}: {e:?}"))
            })?;
        let consensus_block_value =
            parse_required_header(headers, CONSENSUS_BLOCK_VALUE_HEADER, |s| {
                Uint256::from_str_radix(s, 10)
                    .map_err(|e| format!("invalid {CONSENSUS_BLOCK_VALUE_HEADER}: {e:?}"))
            })?;

        Ok(ProduceBlockV3Metadata {
            consensus_version,
            execution_payload_blinded,
            execution_payload_value,
            consensus_block_value,
        })
    }
}

/// A wrapper over a [`SignedBeaconBlock`] or a [`SignedBlockContents`].
#[derive(Clone, Debug, Encode, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub enum PublishBlockRequest<E: EthSpec> {
    BlockContents(SignedBlockContents<E>),
    Block(Arc<SignedBeaconBlock<E>>),
}

impl<E: EthSpec> PublishBlockRequest<E> {
    pub fn new(
        block: Arc<SignedBeaconBlock<E>>,
        blob_items: Option<(KzgProofs<E>, BlobsList<E>)>,
    ) -> Self {
        match blob_items {
            Some((kzg_proofs, blobs)) => Self::BlockContents(SignedBlockContents {
                signed_block: block,
                kzg_proofs,
                blobs,
            }),
            None => Self::Block(block),
        }
    }

    /// SSZ decode with fork variant determined by `fork_name`.
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        if fork_name.deneb_enabled() {
            let mut builder = ssz::SszDecoderBuilder::new(bytes);
            builder.register_anonymous_variable_length_item()?;
            builder.register_type::<KzgProofs<E>>()?;
            builder.register_type::<BlobsList<E>>()?;

            let mut decoder = builder.build()?;
            let block = decoder.decode_next_with(|bytes| {
                SignedBeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name)
            })?;
            let kzg_proofs = decoder.decode_next()?;
            let blobs = decoder.decode_next()?;
            Ok(PublishBlockRequest::new(
                Arc::new(block),
                Some((kzg_proofs, blobs)),
            ))
        } else {
            SignedBeaconBlock::from_ssz_bytes_for_fork(bytes, fork_name)
                .map(|block| PublishBlockRequest::Block(Arc::new(block)))
        }
    }

    pub fn signed_block(&self) -> &Arc<SignedBeaconBlock<E>> {
        match self {
            PublishBlockRequest::BlockContents(block_and_sidecars) => {
                &block_and_sidecars.signed_block
            }
            PublishBlockRequest::Block(block) => block,
        }
    }

    pub fn deconstruct(self) -> SignedBlockContentsTuple<E> {
        match self {
            PublishBlockRequest::BlockContents(block_and_sidecars) => (
                block_and_sidecars.signed_block,
                Some((block_and_sidecars.kzg_proofs, block_and_sidecars.blobs)),
            ),
            PublishBlockRequest::Block(block) => (block, None),
        }
    }
}

impl<E: EthSpec> TryFrom<Arc<SignedBeaconBlock<E>>> for PublishBlockRequest<E> {
    type Error = &'static str;
    fn try_from(block: Arc<SignedBeaconBlock<E>>) -> Result<Self, Self::Error> {
        match *block {
            SignedBeaconBlock::Base(_)
            | SignedBeaconBlock::Altair(_)
            | SignedBeaconBlock::Bellatrix(_)
            | SignedBeaconBlock::Capella(_) => Ok(PublishBlockRequest::Block(block)),
            SignedBeaconBlock::Deneb(_)
            | SignedBeaconBlock::Electra(_)
            | SignedBeaconBlock::EIP7732(_) => Err(
                "post-Deneb block contents cannot be fully constructed from just the signed block",
            ),
        }
    }
}

impl<E: EthSpec> From<SignedBlockContentsTuple<E>> for PublishBlockRequest<E> {
    fn from(block_contents_tuple: SignedBlockContentsTuple<E>) -> Self {
        PublishBlockRequest::new(block_contents_tuple.0, block_contents_tuple.1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBlockContents<E: EthSpec> {
    pub signed_block: Arc<SignedBeaconBlock<E>>,
    pub kzg_proofs: KzgProofs<E>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: BlobsList<E>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
#[serde(bound = "E: EthSpec")]
pub struct BlockContents<E: EthSpec> {
    pub block: BeaconBlock<E>,
    pub kzg_proofs: KzgProofs<E>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: BlobsList<E>,
}

impl<E: EthSpec> ForkVersionDeserialize for BlockContents<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(bound = "E: EthSpec")]
        struct Helper<E: EthSpec> {
            block: serde_json::Value,
            kzg_proofs: KzgProofs<E>,
            #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
            blobs: BlobsList<E>,
        }
        let helper: Helper<E> = serde_json::from_value(value).map_err(serde::de::Error::custom)?;

        Ok(Self {
            block: BeaconBlock::deserialize_by_fork::<'de, D>(helper.block, fork_name)?,
            kzg_proofs: helper.kzg_proofs,
            blobs: helper.blobs,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode)]
#[serde(untagged)]
#[serde(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub enum FullPayloadContents<E: EthSpec> {
    Payload(ExecutionPayload<E>),
    PayloadAndBlobs(ExecutionPayloadAndBlobs<E>),
}

impl<E: EthSpec> FullPayloadContents<E> {
    pub fn new(
        execution_payload: ExecutionPayload<E>,
        maybe_blobs: Option<BlobsBundle<E>>,
    ) -> Self {
        match maybe_blobs {
            None => Self::Payload(execution_payload),
            Some(blobs_bundle) => Self::PayloadAndBlobs(ExecutionPayloadAndBlobs {
                execution_payload,
                blobs_bundle,
            }),
        }
    }

    pub fn payload_ref(&self) -> &ExecutionPayload<E> {
        match self {
            FullPayloadContents::Payload(payload) => payload,
            FullPayloadContents::PayloadAndBlobs(payload_and_blobs) => {
                &payload_and_blobs.execution_payload
            }
        }
    }

    pub fn block_hash(&self) -> ExecutionBlockHash {
        self.payload_ref().block_hash()
    }

    pub fn deconstruct(self) -> (ExecutionPayload<E>, Option<BlobsBundle<E>>) {
        match self {
            FullPayloadContents::Payload(payload) => (payload, None),
            FullPayloadContents::PayloadAndBlobs(payload_and_blobs) => (
                payload_and_blobs.execution_payload,
                Some(payload_and_blobs.blobs_bundle),
            ),
        }
    }
}

impl<E: EthSpec> ForkVersionDeserialize for FullPayloadContents<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Bellatrix | ForkName::Capella => serde_json::from_value(value)
                .map(Self::Payload)
                .map_err(serde::de::Error::custom),
            // TODO(EIP7732): check this
            ForkName::Deneb | ForkName::Electra | ForkName::EIP7732 => {
                serde_json::from_value(value)
                    .map(Self::PayloadAndBlobs)
                    .map_err(serde::de::Error::custom)
            }
            ForkName::Base | ForkName::Altair => Err(serde::de::Error::custom(format!(
                "FullPayloadContents deserialization for {fork_name} not implemented"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode)]
#[serde(bound = "E: EthSpec")]
pub struct ExecutionPayloadAndBlobs<E: EthSpec> {
    pub execution_payload: ExecutionPayload<E>,
    pub blobs_bundle: BlobsBundle<E>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "E: EthSpec")]
pub struct BlobsBundle<E: EthSpec> {
    pub commitments: KzgCommitments<E>,
    pub proofs: KzgProofs<E>,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_fixed_vec")]
    pub blobs: BlobsList<E>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validator_id_serde() {
        let id_str = "\"1\"";
        let x: ValidatorId = serde_json::from_str(id_str).unwrap();
        assert_eq!(x, ValidatorId::Index(1));
        assert_eq!(serde_json::to_string(&x).unwrap(), id_str);

        let pubkey_str = "\"0xb824b5ede33a7b05a378a84b183b4bc7e7db894ce48b659f150c97d359edca2f503081d6678d1200f582ec7cafa9caf2\"";
        let y: ValidatorId = serde_json::from_str(pubkey_str).unwrap();
        assert_eq!(serde_json::to_string(&y).unwrap(), pubkey_str);
    }
}

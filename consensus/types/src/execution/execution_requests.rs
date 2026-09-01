use alloy_primitives::Bytes;
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use ethereum_hashing::{DynamicContext, Sha256Context};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{ProgressiveVariableList, VariableList};
use std::marker::PhantomData;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    builder::{BuilderDepositRequest, BuilderExitRequest},
    consolidation::ConsolidationRequest,
    core::{EthSpec, Hash256},
    deposit::DepositRequest,
    fork::{ForkName, ForkVersionDecode},
    state::BeaconStateError,
    withdrawal::WithdrawalRequest,
};

pub type DepositRequests<E> =
    VariableList<DepositRequest, <E as EthSpec>::MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests<E> =
    VariableList<WithdrawalRequest, <E as EthSpec>::MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests<E> =
    VariableList<ConsolidationRequest, <E as EthSpec>::MaxConsolidationRequestsPerPayload>;
pub type BuilderDepositRequests<E> =
    VariableList<BuilderDepositRequest, <E as EthSpec>::MaxBuilderDepositRequestsPerPayload>;
pub type BuilderExitRequests<E> =
    VariableList<BuilderExitRequest, <E as EthSpec>::MaxBuilderExitRequestsPerPayload>;

/// EIP-7685 execution requests.
///
/// The `Electra` variant is used from Electra through Fulu. The `Gloas` variant uses unbounded
/// progressive lists (EIP-7688), so the old per-list maximums must be enforced at runtime. The
/// builder request lists are new in Gloas (EIP-8282).
#[superstruct(
    variants(Electra, Gloas),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Eq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    specific_variant_attributes(Gloas(tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1, 1, 1)
    ))),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionRequests<E: EthSpec> {
    #[superstruct(only(Electra), partial_getter(rename = "deposits_electra"))]
    pub deposits: DepositRequests<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "deposits_gloas"))]
    pub deposits: ProgressiveVariableList<DepositRequest>,
    #[superstruct(only(Electra), partial_getter(rename = "withdrawals_electra"))]
    pub withdrawals: WithdrawalRequests<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "withdrawals_gloas"))]
    pub withdrawals: ProgressiveVariableList<WithdrawalRequest>,
    #[superstruct(only(Electra), partial_getter(rename = "consolidations_electra"))]
    pub consolidations: ConsolidationRequests<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "consolidations_gloas"))]
    pub consolidations: ProgressiveVariableList<ConsolidationRequest>,
    // [New in Gloas:EIP8282] The builder request lists are only present on the Gloas variant.
    #[superstruct(only(Gloas))]
    pub builder_deposits: ProgressiveVariableList<BuilderDepositRequest>,
    #[superstruct(only(Gloas))]
    pub builder_exits: ProgressiveVariableList<BuilderExitRequest>,
    // Phantom for the unused `E` in the Gloas variant; skipped everywhere.
    #[superstruct(only(Gloas))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom: PhantomData<E>,
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionRequests<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if context.gloas_enabled() {
            ExecutionRequestsGloas::<E>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(ExecutionRequests::Gloas)
        } else {
            ExecutionRequestsElectra::<E>::deserialize(deserializer)
                .map_err(serde::de::Error::custom)
                .map(ExecutionRequests::Electra)
        }
    }
}

impl<E: EthSpec> ForkVersionDecode for ExecutionRequests<E> {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionRequests: {fork_name}",
            ))),
            ForkName::Electra | ForkName::Fulu => {
                ExecutionRequestsElectra::from_ssz_bytes(bytes).map(Self::Electra)
            }
            ForkName::Gloas | ForkName::Heze => {
                ExecutionRequestsGloas::from_ssz_bytes(bytes).map(Self::Gloas)
            }
        }
    }
}

/// Build the EIP-7685 requests list from each request kind's `(request_type, is_empty, ssz_bytes)`.
fn build_execution_requests_list(encoded: Vec<(RequestType, bool, Vec<u8>)>) -> Vec<Bytes> {
    encoded
        .into_iter()
        .filter(|(_, is_empty, _)| !is_empty)
        .map(|(request_type, _, ssz_bytes)| {
            Bytes::from_iter([request_type.to_u8()].into_iter().chain(ssz_bytes))
        })
        .collect()
}

/// Generate the execution layer `requests_hash` based on EIP-7685:
/// `sha256(sha256(requests_0) ++ sha256(requests_1) ++ ...)`.
fn execution_requests_hash(requests_list: &[Bytes]) -> Hash256 {
    let mut hasher = DynamicContext::new();
    for request in requests_list {
        let mut request_hasher = DynamicContext::new();
        request_hasher.update(request);
        hasher.update(&request_hasher.finalize());
    }
    hasher.finalize().into()
}

impl<E: EthSpec> ExecutionRequests<E> {
    /// Returns the encoding according to EIP-7685 to send to the execution layer over the engine
    /// api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        match self {
            Self::Electra(r) => r.get_execution_requests_list(),
            Self::Gloas(r) => r.get_execution_requests_list(),
        }
    }

    /// Generate the execution layer `requests_hash` based on EIP-7685.
    pub fn requests_hash(&self) -> Hash256 {
        execution_requests_hash(&self.get_execution_requests_list())
    }
}

impl<'a, E: EthSpec> ExecutionRequestsRef<'a, E> {
    /// Returns the encoding according to EIP-7685 to send to the execution layer over the engine
    /// api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        match self {
            Self::Electra(r) => r.get_execution_requests_list(),
            Self::Gloas(r) => r.get_execution_requests_list(),
        }
    }

    /// Generate the execution layer `requests_hash` based on EIP-7685.
    pub fn requests_hash(&self) -> Hash256 {
        execution_requests_hash(&self.get_execution_requests_list())
    }
}

impl<E: EthSpec> ExecutionRequestsElectra<E> {
    /// EIP-7685 requests list to send to the EL over the engine API.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        build_execution_requests_list(vec![
            (
                RequestType::Deposit,
                self.deposits.is_empty(),
                self.deposits.as_ssz_bytes(),
            ),
            (
                RequestType::Withdrawal,
                self.withdrawals.is_empty(),
                self.withdrawals.as_ssz_bytes(),
            ),
            (
                RequestType::Consolidation,
                self.consolidations.is_empty(),
                self.consolidations.as_ssz_bytes(),
            ),
        ])
    }
}

impl<E: EthSpec> ExecutionRequestsGloas<E> {
    /// EIP-7685 requests list to send to the EL over the engine API.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        build_execution_requests_list(vec![
            (
                RequestType::Deposit,
                self.deposits.is_empty(),
                self.deposits.as_ssz_bytes(),
            ),
            (
                RequestType::Withdrawal,
                self.withdrawals.is_empty(),
                self.withdrawals.as_ssz_bytes(),
            ),
            (
                RequestType::Consolidation,
                self.consolidations.is_empty(),
                self.consolidations.as_ssz_bytes(),
            ),
            // [New in Gloas:EIP8282]
            (
                RequestType::BuilderDeposit,
                self.builder_deposits.is_empty(),
                self.builder_deposits.as_ssz_bytes(),
            ),
            // [New in Gloas:EIP8282]
            (
                RequestType::BuilderExit,
                self.builder_exits.is_empty(),
                self.builder_exits.as_ssz_bytes(),
            ),
        ])
    }
}

impl<E: EthSpec> From<&ExecutionRequestsElectra<E>> for ExecutionRequestsGloas<E> {
    /// Re-type the bounded (Electra) requests as the progressive Gloas variant. Infallible: the
    /// progressive lists have no capacity limit. The Gloas-only builder request lists start empty.
    fn from(requests: &ExecutionRequestsElectra<E>) -> Self {
        Self {
            deposits: requests.deposits.iter().cloned().collect(),
            withdrawals: requests.withdrawals.iter().cloned().collect(),
            consolidations: requests.consolidations.iter().cloned().collect(),
            builder_deposits: ProgressiveVariableList::default(),
            builder_exits: ProgressiveVariableList::default(),
            _phantom: PhantomData,
        }
    }
}

/// The prefix types for `ExecutionRequest` objects.
#[derive(Debug, Copy, Clone)]
pub enum RequestType {
    Deposit,
    Withdrawal,
    Consolidation,
    BuilderDeposit,
    BuilderExit,
}

impl RequestType {
    pub fn from_u8(prefix: u8) -> Option<Self> {
        match prefix {
            0 => Some(Self::Deposit),
            1 => Some(Self::Withdrawal),
            2 => Some(Self::Consolidation),
            3 => Some(Self::BuilderDeposit),
            4 => Some(Self::BuilderExit),
            _ => None,
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Deposit => 0,
            Self::Withdrawal => 1,
            Self::Consolidation => 2,
            Self::BuilderDeposit => 3,
            Self::BuilderExit => 4,
        }
    }
}

#[cfg(test)]
mod electra_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionRequestsElectra<MainnetEthSpec>);
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionRequestsGloas<MainnetEthSpec>);
}

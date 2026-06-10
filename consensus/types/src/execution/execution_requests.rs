use alloy_primitives::Bytes;
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use ethereum_hashing::{DynamicContext, Sha256Context};
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{ProgressiveVariableList, VariableList};
use std::marker::PhantomData;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    consolidation::ConsolidationRequest,
    core::{EthSpec, Hash256},
    deposit::DepositRequest,
    fork::ForkName,
    withdrawal::WithdrawalRequest,
};

pub type DepositRequests<E> =
    VariableList<DepositRequest, <E as EthSpec>::MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests<E> =
    VariableList<WithdrawalRequest, <E as EthSpec>::MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests<E> =
    VariableList<ConsolidationRequest, <E as EthSpec>::MaxConsolidationRequestsPerPayload>;

/// EIP-7685 execution requests.
///
/// The `Electra` variant (bounded `VariableList`s) is used from Electra through Fulu. The `Gloas`
/// variant \[Modified in Gloas:EIP7688\] uses unbounded `ProgressiveVariableList`s; its per-list
/// `Max*RequestsPerPayload` limits are no longer enforced by the type and MUST be checked at
/// runtime where the spec requires it.
#[superstruct(
    variants(Electra, Gloas),
    variant_attributes(
        derive(
            Debug,
            Default,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        educe(PartialEq, Eq, Hash(bound(E: EthSpec))),
        context_deserialize(ForkName),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    specific_variant_attributes(Gloas(tree_hash(
        struct_behaviour = "progressive_container",
        active_fields(1, 1, 1)
    ))),
    cast_error(ty = "String", expr = "String::from(\"unexpected execution requests variant\")"),
    partial_getter_error(
        ty = "String",
        expr = "String::from(\"unexpected execution requests variant\")"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
#[educe(PartialEq)]
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
    // Phantom for the unused `E` in the Gloas variant; skipped everywhere.
    #[superstruct(only(Gloas))]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for ExecutionRequests<E> {
    fn default() -> Self {
        Self::Electra(ExecutionRequestsElectra::default())
    }
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

/// Build the EIP-7685 requests list from each request kind's `(is_empty, ssz_bytes)`.
fn build_execution_requests_list(encoded: [(RequestType, bool, Vec<u8>); 3]) -> Vec<Bytes> {
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

/// Implements the EIP-7685 requests list/hash accessors for an `ExecutionRequests` variant.
macro_rules! impl_execution_requests_accessors {
    ($variant:ident) => {
        impl<E: EthSpec> $variant<E> {
            /// EIP-7685 requests list to send to the EL over the engine API.
            pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
                build_execution_requests_list([
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

            /// EIP-7685 `requests_hash`.
            pub fn requests_hash(&self) -> Hash256 {
                execution_requests_hash(&self.get_execution_requests_list())
            }
        }
    };
}

impl_execution_requests_accessors!(ExecutionRequestsElectra);
impl_execution_requests_accessors!(ExecutionRequestsGloas);

impl<E: EthSpec> From<&ExecutionRequestsElectra<E>> for ExecutionRequestsGloas<E> {
    /// Re-type the bounded (Electra) requests as the progressive Gloas variant. Infallible: the
    /// progressive lists have no capacity limit.
    fn from(requests: &ExecutionRequestsElectra<E>) -> Self {
        Self {
            deposits: requests.deposits.iter().cloned().collect(),
            withdrawals: requests.withdrawals.iter().cloned().collect(),
            consolidations: requests.consolidations.iter().cloned().collect(),
            _phantom: std::marker::PhantomData,
        }
    }
}

/// The prefix types for `ExecutionRequest` objects.
#[derive(Debug, Copy, Clone)]
pub enum RequestType {
    Deposit,
    Withdrawal,
    Consolidation,
}

impl RequestType {
    pub fn from_u8(prefix: u8) -> Option<Self> {
        match prefix {
            0 => Some(Self::Deposit),
            1 => Some(Self::Withdrawal),
            2 => Some(Self::Consolidation),
            _ => None,
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Deposit => 0,
            Self::Withdrawal => 1,
            Self::Consolidation => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MainnetEthSpec;

    use super::*;

    ssz_and_tree_hash_tests!(ExecutionRequestsElectra<MainnetEthSpec>);

    mod gloas {
        use super::*;
        ssz_and_tree_hash_tests!(ExecutionRequestsGloas<MainnetEthSpec>);
    }
}

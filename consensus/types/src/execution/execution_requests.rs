use alloy_primitives::Bytes;
use context_deserialize::context_deserialize;
use educe::Educe;
use ethereum_hashing::{DynamicContext, Sha256Context};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
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
use ssz::Decode;

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
#[derive(Debug, Educe, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[serde(bound = "E: EthSpec", untagged)]
#[educe(PartialEq, Eq, Hash(bound(E: EthSpec)))]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionRequests<E: EthSpec> {
    pub deposits: DepositRequests<E>,
    pub withdrawals: WithdrawalRequests<E>,
    pub consolidations: ConsolidationRequests<E>,
    #[superstruct(only(Gloas))]
    pub builder_deposits: BuilderDepositRequests<E>,
    #[superstruct(only(Gloas))]
    pub builder_exits: BuilderExitRequests<E>,
}

impl<'a, E: EthSpec> ExecutionRequestsRef<'a, E> {
    /// Returns the encoding according to EIP-7685 to send
    /// to the execution layer over the engine api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        let mut requests_list = Vec::new();
        if !self.deposits().is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Deposit.to_u8()]
                    .into_iter()
                    .chain(self.deposits().as_ssz_bytes()),
            ));
        }
        if !self.withdrawals().is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Withdrawal.to_u8()]
                    .into_iter()
                    .chain(self.withdrawals().as_ssz_bytes()),
            ));
        }
        if !self.consolidations().is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Consolidation.to_u8()]
                    .into_iter()
                    .chain(self.consolidations().as_ssz_bytes()),
            ));
        }
        // [New in Gloas:EIP8282] The builder request lists are only present on the Gloas variant.
        if let Ok(builder_deposits) = self.builder_deposits()
            && !builder_deposits.is_empty()
        {
            requests_list.push(Bytes::from_iter(
                [RequestType::BuilderDeposit.to_u8()]
                    .into_iter()
                    .chain(builder_deposits.as_ssz_bytes()),
            ));
        }
        if let Ok(builder_exits) = self.builder_exits()
            && !builder_exits.is_empty()
        {
            requests_list.push(Bytes::from_iter(
                [RequestType::BuilderExit.to_u8()]
                    .into_iter()
                    .chain(builder_exits.as_ssz_bytes()),
            ));
        }
        requests_list
    }

    /// Generate the execution layer `requests_hash` based on EIP-7685.
    ///
    /// `sha256(sha256(requests_0) ++ sha256(requests_1) ++ ...)`
    pub fn requests_hash(&self) -> Hash256 {
        let mut hasher = DynamicContext::new();

        for request in self.get_execution_requests_list().iter() {
            let mut request_hasher = DynamicContext::new();
            request_hasher.update(request);
            let request_hash = request_hasher.finalize();

            hasher.update(&request_hash);
        }

        hasher.finalize().into()
    }
}

impl<E: EthSpec> ExecutionRequests<E> {
    /// Returns the encoding according to EIP-7685 to send
    /// to the execution layer over the engine api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        self.to_ref().get_execution_requests_list()
    }

    /// Generate the execution layer `requests_hash` based on EIP-7685.
    pub fn requests_hash(&self) -> Hash256 {
        self.to_ref().requests_hash()
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
            ForkName::Gloas => ExecutionRequestsGloas::from_ssz_bytes(bytes).map(Self::Gloas),
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

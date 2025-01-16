use crate::test_utils::TestRandom;
use crate::{ConsolidationRequest, DepositRequest, EthSpec, Hash256, WithdrawalRequest};
use alloy_primitives::Bytes;
use derivative::Derivative;
use ethereum_hashing::{DynamicContext, Sha256Context};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type DepositRequests<E> =
    VariableList<DepositRequest, <E as EthSpec>::MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests<E> =
    VariableList<WithdrawalRequest, <E as EthSpec>::MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests<E> =
    VariableList<ConsolidationRequest, <E as EthSpec>::MaxConsolidationRequestsPerPayload>;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    Derivative,
    Default,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct ExecutionRequests<E: EthSpec> {
    pub deposits: DepositRequests<E>,
    pub withdrawals: WithdrawalRequests<E>,
    pub consolidations: ConsolidationRequests<E>,
}

impl<E: EthSpec> ExecutionRequests<E> {
    /// Returns the encoding according to EIP-7685 to send
    /// to the execution layer over the engine api.
    pub fn get_execution_requests_list(&self) -> Vec<Bytes> {
        let mut requests_list = Vec::new();
        if !self.deposits.is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Deposit.to_u8()]
                    .into_iter()
                    .chain(self.deposits.as_ssz_bytes()),
            ));
        }
        if !self.withdrawals.is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Withdrawal.to_u8()]
                    .into_iter()
                    .chain(self.withdrawals.as_ssz_bytes()),
            ));
        }
        if !self.consolidations.is_empty() {
            requests_list.push(Bytes::from_iter(
                [RequestType::Consolidation.to_u8()]
                    .into_iter()
                    .chain(self.consolidations.as_ssz_bytes()),
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

    ssz_and_tree_hash_tests!(ExecutionRequests<MainnetEthSpec>);
}

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
        let deposit_bytes = Bytes::from(self.deposits.as_ssz_bytes());
        let withdrawal_bytes = Bytes::from(self.withdrawals.as_ssz_bytes());
        let consolidation_bytes = Bytes::from(self.consolidations.as_ssz_bytes());
        vec![deposit_bytes, withdrawal_bytes, consolidation_bytes]
    }

    /// Generate the execution layer `requests_hash` based on EIP-7685.
    ///
    /// `sha256(sha256(requests_0) ++ sha256(requests_1) ++ ...)`
    pub fn requests_hash(&self) -> Hash256 {
        let mut hasher = DynamicContext::new();

        for (i, request) in self.get_execution_requests_list().iter().enumerate() {
            let mut request_hasher = DynamicContext::new();
            request_hasher.update(&[i as u8]);
            request_hasher.update(request);
            let request_hash = request_hasher.finalize();

            hasher.update(&request_hash);
        }

        hasher.finalize().into()
    }
}

/// This is used to index into the `execution_requests` array.
#[derive(Debug, Copy, Clone)]
pub enum RequestPrefix {
    Deposit,
    Withdrawal,
    Consolidation,
}

impl RequestPrefix {
    pub fn from_prefix(prefix: u8) -> Option<Self> {
        match prefix {
            0 => Some(Self::Deposit),
            1 => Some(Self::Withdrawal),
            2 => Some(Self::Consolidation),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::MainnetEthSpec;

    use super::*;

    ssz_and_tree_hash_tests!(ExecutionRequests<MainnetEthSpec>);
}

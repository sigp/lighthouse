use crate::{
    BeaconNodeHttpClient, Error,
    types::{BlockId, StateId},
};
use serde::{Deserialize, Serialize};
use types::{ForkName, SszProof};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SszProofResponse {
    pub version: ForkName,
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: SszProof,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SszProofQuery {
    #[serde(with = "serde_utils::quoted_u64")]
    pub gindex: u64,
}

impl BeaconNodeHttpClient {
    /// `GET lighthouse/beacon/states/{state_id}/proof?gindex={gindex}`
    pub async fn get_lighthouse_state_proof(
        &self,
        state_id: StateId,
        gindex: u64,
    ) -> Result<SszProofResponse, Error> {
        let mut path = self.server.expose_full().clone();
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .pop_if_empty()
            .push("lighthouse")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("proof");
        path.query_pairs_mut()
            .append_pair("gindex", &gindex.to_string());
        self.get(path).await
    }

    /// `GET lighthouse/beacon/blocks/{block_id}/proof?gindex={gindex}`
    pub async fn get_lighthouse_block_proof(
        &self,
        block_id: BlockId,
        gindex: u64,
    ) -> Result<SszProofResponse, Error> {
        let mut path = self.server.expose_full().clone();
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .pop_if_empty()
            .push("lighthouse")
            .push("beacon")
            .push("blocks")
            .push(&block_id.to_string())
            .push("proof");
        path.query_pairs_mut()
            .append_pair("gindex", &gindex.to_string());
        self.get(path).await
    }
}

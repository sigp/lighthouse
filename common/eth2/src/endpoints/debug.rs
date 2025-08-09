//! Debug API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1, V2};
use crate::types::*;
use reqwest::Url;
use types::{ChainSpec, EthSpec};
use types::fork_versioned_response::ExecutionOptimisticFinalizedForkVersionedResponse;

impl BeaconNodeHttpClient {
    // ===============================
    // Beacon State Debug Endpoints
    // ===============================

    /// URL path for `v2/debug/beacon/states/{state_id}`.
    pub fn get_debug_beacon_states_path(&self, state_id: StateId) -> Result<Url, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("debug")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string());
        Ok(path)
    }

    /// `GET v2/debug/beacon/states/{state_id}`
    pub async fn get_debug_beacon_states<E: EthSpec>(
        &self,
        state_id: StateId,
    ) -> Result<Option<ExecutionOptimisticFinalizedForkVersionedResponse<BeaconState<E>>>, Error>
    {
        let path = self.get_debug_beacon_states_path(state_id)?;
        self.get_opt(path).await
    }

    /// `GET debug/beacon/states/{state_id}`
    /// `-H "accept: application/octet-stream"`
    pub async fn get_debug_beacon_states_ssz<E: EthSpec>(
        &self,
        state_id: StateId,
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        let path = self.get_debug_beacon_states_path(state_id)?;
        self.get_bytes_opt_accept_header(path, Accept::Ssz, self.timeouts().get_debug_beacon_states)
            .await?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    // ===============================
    // Beacon Chain Head Debug Endpoints
    // ===============================

    /// `GET v2/debug/beacon/heads`
    pub async fn get_debug_beacon_heads(
        &self,
    ) -> Result<GenericResponse<Vec<ChainHeadData>>, Error> {
        let mut path = self.eth_path(V2)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("debug")
            .push("beacon")
            .push("heads");
        self.get(path).await
    }

    /// `GET v1/debug/beacon/heads` (LEGACY)
    pub async fn get_debug_beacon_heads_v1(
        &self,
    ) -> Result<GenericResponse<Vec<ChainHeadData>>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("debug")
            .push("beacon")
            .push("heads");
        self.get(path).await
    }

    // ===============================
    // Fork Choice Debug Endpoints
    // ===============================

    /// `GET v1/debug/fork_choice`
    pub async fn get_debug_fork_choice(&self) -> Result<ForkChoice, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("debug")
            .push("fork_choice");
        self.get(path).await
    }
}
//! Configuration API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1};
use crate::types::*;
use serde::{de::DeserializeOwned, Serialize};

impl BeaconNodeHttpClient {
    /// `GET config/fork_schedule`
    /// 
    /// Retrieve all scheduled hard forks for the configured network.
    pub async fn get_config_fork_schedule(&self) -> Result<GenericResponse<Vec<Fork>>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("config")
            .push("fork_schedule");

        self.get(path).await
    }

    /// `GET config/spec`
    ///
    /// Retrieve specification configuration used on this node.
    pub async fn get_config_spec<T: Serialize + DeserializeOwned>(
        &self,
    ) -> Result<GenericResponse<T>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("config")
            .push("spec");

        self.get(path).await
    }

    /// `GET config/deposit_contract`
    ///
    /// Retrieve Eth1 deposit contract address and chain ID.
    pub async fn get_config_deposit_contract(
        &self,
    ) -> Result<GenericResponse<DepositContractData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("config")
            .push("deposit_contract");

        self.get(path).await
    }
}
//! Node management API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1};
use crate::types::*;
use libp2p_identity::PeerId;
use reqwest::StatusCode;

impl BeaconNodeHttpClient {
    /// `GET node/version`
    ///
    /// Requests the string representation of the version, from a node directly.
    pub async fn get_node_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("version");

        self.get(path).await
    }

    /// `GET node/identity`
    ///
    /// Requests that the beacon node identify information about itself.
    /// It is primarily used as an aid for discovery.
    pub async fn get_node_identity(&self) -> Result<GenericResponse<IdentityData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("identity");

        self.get(path).await
    }

    /// `GET node/syncing`
    ///
    /// Requests the beacon node to describe if it's currently syncing or not,
    /// and if it is, what block it is up to.
    pub async fn get_node_syncing(&self) -> Result<GenericResponse<SyncingData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("syncing");

        self.get(path).await
    }

    /// `GET node/health`
    ///
    /// Returns node health status in HTTP status codes:
    /// - 200: Node is ready
    /// - 206: Node is syncing but can serve incomplete data
    /// - 503: Node not initialized or having issues
    pub async fn get_node_health(&self) -> Result<StatusCode, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("health");

        let status = self.client.get(path).send().await?.status();
        if status == StatusCode::OK || status == StatusCode::PARTIAL_CONTENT {
            Ok(status)
        } else {
            Err(Error::StatusCode(status))
        }
    }

    /// `GET node/peers/{peer_id}`
    ///
    /// Retrieves data about the given peer.
    pub async fn get_node_peers_by_id(
        &self,
        peer_id: PeerId,
    ) -> Result<GenericResponse<PeerData>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("peers")
            .push(&peer_id.to_string());

        self.get(path).await
    }

    /// `GET node/peers`
    ///
    /// Retrieves data about the node's network peers. By default returns all peers.
    /// Multiple query params are combined using AND condition.
    pub async fn get_node_peers(
        &self,
        states: Option<&[PeerState]>,
        directions: Option<&[PeerDirection]>,
    ) -> Result<PeersData, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("peers");

        if let Some(states) = states {
            let state_string = states
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("state", &state_string);
        }

        if let Some(directions) = directions {
            let dir_string = directions
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(",");
            path.query_pairs_mut().append_pair("direction", &dir_string);
        }

        self.get(path).await
    }

    /// `GET node/peer_count`
    ///
    /// Retrieves number of known peers.
    pub async fn get_node_peer_count(&self) -> Result<GenericResponse<PeerCount>, Error> {
        let mut path = self.eth_path(V1)?;

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("node")
            .push("peer_count");

        self.get(path).await
    }
}
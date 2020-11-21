//! This module contains endpoints that are non-standard and only available on Lighthouse servers.

use crate::{
    ok_or_error,
    types::{BeaconState, Epoch, EthSpec, GenericResponse, ValidatorId},
    BeaconNodeHttpClient, DepositData, Error, Eth1Data, Hash256, StateId, StatusCode,
};
use proto_array::core::ProtoArray;
use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};

pub use eth2_libp2p::{types::SyncState, PeerInfo};

/// Information returned by `peers` and `connected_peers`.
// TODO: this should be deserializable..
#[derive(Debug, Clone, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct Peer<T: EthSpec> {
    /// The Peer's ID
    pub peer_id: String,
    /// The PeerInfo associated with the peer.
    pub peer_info: PeerInfo<T>,
}

/// The results of validators voting during an epoch.
///
/// Provides information about the current and previous epochs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalValidatorInclusionData {
    /// The total effective balance of all active validators during the _current_ epoch.
    pub current_epoch_active_gwei: u64,
    /// The total effective balance of all active validators during the _previous_ epoch.
    pub previous_epoch_active_gwei: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch.
    pub current_epoch_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _current_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _current_ epoch.
    pub current_epoch_target_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch.
    pub previous_epoch_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _previous_ epoch.
    pub previous_epoch_target_attesting_gwei: u64,
    /// The total effective balance of all validators who attested during the _previous_ epoch and
    /// agreed with the state about the beacon block at the time of attestation.
    pub previous_epoch_head_attesting_gwei: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorInclusionData {
    /// True if the validator has been slashed, ever.
    pub is_slashed: bool,
    /// True if the validator can withdraw in the current epoch.
    pub is_withdrawable_in_current_epoch: bool,
    /// True if the validator was active in the state's _current_ epoch.
    pub is_active_in_current_epoch: bool,
    /// True if the validator was active in the state's _previous_ epoch.
    pub is_active_in_previous_epoch: bool,
    /// The validator's effective balance in the _current_ epoch.
    pub current_epoch_effective_balance_gwei: u64,
    /// True if the validator had an attestation included in the _current_ epoch.
    pub is_current_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _current_
    /// epoch matches the block root known to the state.
    pub is_current_epoch_target_attester: bool,
    /// True if the validator had an attestation included in the _previous_ epoch.
    pub is_previous_epoch_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _previous_
    /// epoch matches the block root known to the state.
    pub is_previous_epoch_target_attester: bool,
    /// True if the validator's beacon block root attestation in the _previous_ epoch at the
    /// attestation's slot (`attestation_data.slot`) matches the block root known to the state.
    pub is_previous_epoch_head_attester: bool,
}

#[cfg(target_os = "linux")]
use {procinfo::pid, psutil::process::Process};

/// Reports on the health of the Lighthouse instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// The pid of this process.
    pub pid: u32,
    /// The number of threads used by this pid.
    pub pid_num_threads: i32,
    /// The total resident memory used by this pid.
    pub pid_mem_resident_set_size: u64,
    /// The total virtual memory used by this pid.
    pub pid_mem_virtual_memory_size: u64,
    /// Total virtual memory on the system
    pub sys_virt_mem_total: u64,
    /// Total virtual memory available for new processes.
    pub sys_virt_mem_available: u64,
    /// Total virtual memory used on the system
    pub sys_virt_mem_used: u64,
    /// Total virtual memory not used on the system
    pub sys_virt_mem_free: u64,
    /// Percentage of virtual memory used on the system
    pub sys_virt_mem_percent: f32,
    /// System load average over 1 minute.
    pub sys_loadavg_1: f64,
    /// System load average over 5 minutes.
    pub sys_loadavg_5: f64,
    /// System load average over 15 minutes.
    pub sys_loadavg_15: f64,
}

impl Health {
    #[cfg(not(target_os = "linux"))]
    pub fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    pub fn observe() -> Result<Self, String> {
        let process =
            Process::current().map_err(|e| format!("Unable to get current process: {:?}", e))?;

        let process_mem = process
            .memory_info()
            .map_err(|e| format!("Unable to get process memory info: {:?}", e))?;

        let stat = pid::stat_self().map_err(|e| format!("Unable to get stat: {:?}", e))?;

        let vm = psutil::memory::virtual_memory()
            .map_err(|e| format!("Unable to get virtual memory: {:?}", e))?;
        let loadavg =
            psutil::host::loadavg().map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        Ok(Self {
            pid: process.pid(),
            pid_num_threads: stat.num_threads,
            pid_mem_resident_set_size: process_mem.rss(),
            pid_mem_virtual_memory_size: process_mem.vms(),
            sys_virt_mem_total: vm.total(),
            sys_virt_mem_available: vm.available(),
            sys_virt_mem_used: vm.used(),
            sys_virt_mem_free: vm.free(),
            sys_virt_mem_percent: vm.percent(),
            sys_loadavg_1: loadavg.one,
            sys_loadavg_5: loadavg.five,
            sys_loadavg_15: loadavg.fifteen,
        })
    }
}

/// Indicates how up-to-date the Eth1 caches are.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Eth1SyncStatusData {
    pub head_block_number: Option<u64>,
    pub head_block_timestamp: Option<u64>,
    pub latest_cached_block_number: Option<u64>,
    pub latest_cached_block_timestamp: Option<u64>,
    pub voting_target_timestamp: u64,
    pub eth1_node_sync_status_percentage: f64,
    pub lighthouse_is_cached_and_ready: bool,
}

/// A fully parsed eth1 deposit contract log.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct DepositLog {
    pub deposit_data: DepositData,
    /// The block number of the log that included this `DepositData`.
    pub block_number: u64,
    /// The index included with the deposit log.
    pub index: u64,
    /// True if the signature is valid.
    pub signature_is_valid: bool,
}

/// A block of the eth1 chain.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Eth1Block {
    pub hash: Hash256,
    pub timestamp: u64,
    pub number: u64,
    pub deposit_root: Option<Hash256>,
    pub deposit_count: Option<u64>,
}

impl Eth1Block {
    pub fn eth1_data(self) -> Option<Eth1Data> {
        Some(Eth1Data {
            deposit_root: self.deposit_root?,
            deposit_count: self.deposit_count?,
            block_hash: self.hash,
        })
    }
}

impl BeaconNodeHttpClient {
    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_bytes_opt<U: IntoUrl>(&self, url: U) -> Result<Option<Vec<u8>>, Error> {
        let response = self.client.get(url).send().await.map_err(Error::Reqwest)?;
        match ok_or_error(response).await {
            Ok(resp) => Ok(Some(
                resp.bytes()
                    .await
                    .map_err(Error::Reqwest)?
                    .into_iter()
                    .collect::<Vec<_>>(),
            )),
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// `GET lighthouse/health`
    pub async fn get_lighthouse_health(&self) -> Result<GenericResponse<Health>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("health");

        self.get(path).await
    }

    /// `GET lighthouse/syncing`
    pub async fn get_lighthouse_syncing(&self) -> Result<GenericResponse<SyncState>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("syncing");

        self.get(path).await
    }

    /*
     * Note:
     *
     * The `lighthouse/peers` endpoints do not have functions here. We are yet to implement
     * `Deserialize` on the `PeerInfo` struct since it contains use of `Instant`. This could be
     * fairly simply achieved, if desired.
     */

    /// `GET lighthouse/proto_array`
    pub async fn get_lighthouse_proto_array(&self) -> Result<GenericResponse<ProtoArray>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("proto_array");

        self.get(path).await
    }

    /// `GET lighthouse/validator_inclusion/{epoch}/global`
    pub async fn get_lighthouse_validator_inclusion_global(
        &self,
        epoch: Epoch,
    ) -> Result<GenericResponse<GlobalValidatorInclusionData>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validator_inclusion")
            .push(&epoch.to_string())
            .push("global");

        self.get(path).await
    }

    /// `GET lighthouse/validator_inclusion/{epoch}/{validator_id}`
    pub async fn get_lighthouse_validator_inclusion(
        &self,
        epoch: Epoch,
        validator_id: ValidatorId,
    ) -> Result<GenericResponse<Option<ValidatorInclusionData>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validator_inclusion")
            .push(&epoch.to_string())
            .push(&validator_id.to_string());

        self.get(path).await
    }

    /// `GET lighthouse/eth1/syncing`
    pub async fn get_lighthouse_eth1_syncing(
        &self,
    ) -> Result<GenericResponse<Eth1SyncStatusData>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("eth1")
            .push("syncing");

        self.get(path).await
    }

    /// `GET lighthouse/eth1/block_cache`
    pub async fn get_lighthouse_eth1_block_cache(
        &self,
    ) -> Result<GenericResponse<Vec<Eth1Block>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("eth1")
            .push("block_cache");

        self.get(path).await
    }

    /// `GET lighthouse/eth1/deposit_cache`
    pub async fn get_lighthouse_eth1_deposit_cache(
        &self,
    ) -> Result<GenericResponse<Vec<DepositLog>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("eth1")
            .push("deposit_cache");

        self.get(path).await
    }

    /// `GET lighthouse/beacon/states/{state_id}/ssz`
    pub async fn get_lighthouse_beacon_states_ssz<E: EthSpec>(
        &self,
        state_id: &StateId,
    ) -> Result<Option<BeaconState<E>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("ssz");

        self.get_bytes_opt(path)
            .await?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes).map_err(Error::InvalidSsz))
            .transpose()
    }
}

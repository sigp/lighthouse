//! This module contains endpoints that are non-standard and only available on Lighthouse servers.

use crate::{
    ok_or_error,
    types::{BeaconState, ChainSpec, Epoch, EthSpec, GenericResponse, ValidatorId},
    BeaconNodeHttpClient, DepositData, Error, Eth1Data, Hash256, StateId, StatusCode,
};
use proto_array::core::ProtoArray;
use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};
use ssz::four_byte_option_impl;
use ssz_derive::{Decode, Encode};
use store::{AnchorInfo, Split};

pub use eth2_libp2p::{types::SyncState, PeerInfo};

// Define "legacy" implementations of `Option<T>` which use four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_u64, u64);
four_byte_option_impl!(four_byte_option_hash256, Hash256);

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
    /// The total effective balance of all validators who attested during the _current_ epoch and
    /// agreed with the state about the beacon block at the first slot of the _current_ epoch.
    pub current_epoch_target_attesting_gwei: u64,
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
    /// True if the validator was active and not slashed in the state's _current_ epoch.
    pub is_active_unslashed_in_current_epoch: bool,
    /// True if the validator was active and not slashed in the state's _previous_ epoch.
    pub is_active_unslashed_in_previous_epoch: bool,
    /// The validator's effective balance in the _current_ epoch.
    pub current_epoch_effective_balance_gwei: u64,
    /// True if the validator's beacon block root attestation for the first slot of the _current_
    /// epoch matches the block root known to the state.
    pub is_current_epoch_target_attester: bool,
    /// True if the validator's beacon block root attestation for the first slot of the _previous_
    /// epoch matches the block root known to the state.
    pub is_previous_epoch_target_attester: bool,
    /// True if the validator's beacon block root attestation in the _previous_ epoch at the
    /// attestation's slot (`attestation_data.slot`) matches the block root known to the state.
    pub is_previous_epoch_head_attester: bool,
}

#[cfg(target_os = "linux")]
use {
    procinfo::pid, psutil::cpu::os::linux::CpuTimesExt,
    psutil::memory::os::linux::VirtualMemoryExt, psutil::process::Process,
};

/// Reports on the health of the Lighthouse instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Health {
    #[serde(flatten)]
    pub system: SystemHealth,
    #[serde(flatten)]
    pub process: ProcessHealth,
}

/// System related health.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SystemHealth {
    /// Total virtual memory on the system
    pub sys_virt_mem_total: u64,
    /// Total virtual memory available for new processes.
    pub sys_virt_mem_available: u64,
    /// Total virtual memory used on the system.
    pub sys_virt_mem_used: u64,
    /// Total virtual memory not used on the system.
    pub sys_virt_mem_free: u64,
    /// Percentage of virtual memory used on the system.
    pub sys_virt_mem_percent: f32,
    /// Total cached virtual memory on the system.
    pub sys_virt_mem_cached: u64,
    /// Total buffered virtual memory on the system.
    pub sys_virt_mem_buffers: u64,

    /// System load average over 1 minute.
    pub sys_loadavg_1: f64,
    /// System load average over 5 minutes.
    pub sys_loadavg_5: f64,
    /// System load average over 15 minutes.
    pub sys_loadavg_15: f64,

    /// Total cpu cores.
    pub cpu_cores: u64,
    /// Total cpu threads.
    pub cpu_threads: u64,

    /// Total time spent in kernel mode.
    pub system_seconds_total: u64,
    /// Total time spent in user mode.
    pub user_seconds_total: u64,
    /// Total time spent in waiting for io.
    pub iowait_seconds_total: u64,
    /// Total idle cpu time.
    pub idle_seconds_total: u64,
    /// Total cpu time.
    pub cpu_time_total: u64,

    /// Total capacity of disk.
    pub disk_node_bytes_total: u64,
    /// Free space in disk.
    pub disk_node_bytes_free: u64,
    /// Number of disk reads.
    pub disk_node_reads_total: u64,
    /// Number of disk writes.
    pub disk_node_writes_total: u64,

    /// Total bytes received over all network interfaces.
    pub network_node_bytes_total_received: u64,
    /// Total bytes sent over all network interfaces.
    pub network_node_bytes_total_transmit: u64,

    /// Boot time
    pub misc_node_boot_ts_seconds: u64,
    /// OS
    pub misc_os: String,
}

impl SystemHealth {
    #[cfg(not(target_os = "linux"))]
    pub fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    pub fn observe() -> Result<Self, String> {
        let vm = psutil::memory::virtual_memory()
            .map_err(|e| format!("Unable to get virtual memory: {:?}", e))?;
        let loadavg =
            psutil::host::loadavg().map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        let cpu =
            psutil::cpu::cpu_times().map_err(|e| format!("Unable to get cpu times: {:?}", e))?;

        let disk_usage = psutil::disk::disk_usage("/")
            .map_err(|e| format!("Unable to disk usage info: {:?}", e))?;

        let disk = psutil::disk::DiskIoCountersCollector::default()
            .disk_io_counters()
            .map_err(|e| format!("Unable to get disk counters: {:?}", e))?;

        let net = psutil::network::NetIoCountersCollector::default()
            .net_io_counters()
            .map_err(|e| format!("Unable to get network io counters: {:?}", e))?;

        let boot_time = psutil::host::boot_time()
            .map_err(|e| format!("Unable to get system boot time: {:?}", e))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Boot time is lower than unix epoch: {}", e))?
            .as_secs();

        Ok(Self {
            sys_virt_mem_total: vm.total(),
            sys_virt_mem_available: vm.available(),
            sys_virt_mem_used: vm.used(),
            sys_virt_mem_free: vm.free(),
            sys_virt_mem_cached: vm.cached(),
            sys_virt_mem_buffers: vm.buffers(),
            sys_virt_mem_percent: vm.percent(),
            sys_loadavg_1: loadavg.one,
            sys_loadavg_5: loadavg.five,
            sys_loadavg_15: loadavg.fifteen,
            cpu_cores: psutil::cpu::cpu_count_physical(),
            cpu_threads: psutil::cpu::cpu_count(),
            system_seconds_total: cpu.system().as_secs(),
            cpu_time_total: cpu.total().as_secs(),
            user_seconds_total: cpu.user().as_secs(),
            iowait_seconds_total: cpu.iowait().as_secs(),
            idle_seconds_total: cpu.idle().as_secs(),
            disk_node_bytes_total: disk_usage.total(),
            disk_node_bytes_free: disk_usage.free(),
            disk_node_reads_total: disk.read_count(),
            disk_node_writes_total: disk.write_count(),
            network_node_bytes_total_received: net.bytes_recv(),
            network_node_bytes_total_transmit: net.bytes_sent(),
            misc_node_boot_ts_seconds: boot_time,
            misc_os: std::env::consts::OS.to_string(),
        })
    }
}

/// Process specific health
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessHealth {
    /// The pid of this process.
    pub pid: u32,
    /// The number of threads used by this pid.
    pub pid_num_threads: i32,
    /// The total resident memory used by this pid.
    pub pid_mem_resident_set_size: u64,
    /// The total virtual memory used by this pid.
    pub pid_mem_virtual_memory_size: u64,
    /// Number of cpu seconds consumed by this pid.
    pub pid_process_seconds_total: u64,
}

impl ProcessHealth {
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
        let process_times = process
            .cpu_times()
            .map_err(|e| format!("Unable to get process cpu times : {:?}", e))?;

        Ok(Self {
            pid: process.pid(),
            pid_num_threads: stat.num_threads,
            pid_mem_resident_set_size: process_mem.rss(),
            pid_mem_virtual_memory_size: process_mem.vms(),
            pid_process_seconds_total: process_times.busy().as_secs()
                + process_times.children_system().as_secs()
                + process_times.children_system().as_secs(),
        })
    }
}

impl Health {
    #[cfg(not(target_os = "linux"))]
    pub fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    pub fn observe() -> Result<Self, String> {
        Ok(Self {
            process: ProcessHealth::observe()?,
            system: SystemHealth::observe()?,
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
    #[ssz(with = "four_byte_option_hash256")]
    pub deposit_root: Option<Hash256>,
    #[ssz(with = "four_byte_option_u64")]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub schema_version: u64,
    pub split: Split,
    pub anchor: Option<AnchorInfo>,
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
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("health");

        self.get(path).await
    }

    /// `GET lighthouse/syncing`
    pub async fn get_lighthouse_syncing(&self) -> Result<GenericResponse<SyncState>, Error> {
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        let mut path = self.server.full.clone();

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
        spec: &ChainSpec,
    ) -> Result<Option<BeaconState<E>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("beacon")
            .push("states")
            .push(&state_id.to_string())
            .push("ssz");

        self.get_bytes_opt(path)
            .await?
            .map(|bytes| BeaconState::from_ssz_bytes(&bytes, spec).map_err(Error::InvalidSsz))
            .transpose()
    }

    /// `GET lighthouse/staking`
    pub async fn get_lighthouse_staking(&self) -> Result<bool, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("staking");

        self.get_opt::<(), _>(path).await.map(|opt| opt.is_some())
    }

    /// `GET lighthouse/database/info`
    pub async fn get_lighthouse_database_info(&self) -> Result<DatabaseInfo, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("database")
            .push("info");

        self.get(path).await
    }

    /// `POST lighthouse/database/reconstruct`
    pub async fn post_lighthouse_database_reconstruct(&self) -> Result<String, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("database")
            .push("reconstruct");

        self.post_with_response(path, &()).await
    }
}

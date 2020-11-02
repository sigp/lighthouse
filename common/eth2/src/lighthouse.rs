//! This module contains endpoints that are non-standard and only available on Lighthouse servers.

use crate::{
    ok_or_error,
    types::{BeaconState, Epoch, EthSpec, GenericResponse, ValidatorId},
    BeaconNodeHttpClient, Error, StateId, StatusCode,
};
use proto_array::core::ProtoArray;
use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};
use ssz::Decode;
use std::path::{Path, PathBuf};
use sysinfo::{NetworkExt, NetworksExt, System as SystemInfo, SystemExt};
use systemstat::{Platform, System as SystemStat};

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

#[cfg(target_os = "macos")]
use psutil::process::Process;
#[cfg(target_os = "linux")]
use psutil::process::Process;

/// Reports information about the system the Lighthouse instance is running on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct System {
    pub health: Health,
    pub drives: Vec<Drive>,
}

impl System {
    pub fn observe() -> Result<Self, String> {
        Ok(Self {
            health: Health::observe()?,
            drives: Drive::observe()?,
        })
    }
}

/// Contains information about a file system mount.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MountInfo {
    avail: u64,
    total: u64,
    used: u64,
    used_pct: f64,
    mounted_on: PathBuf,
}

impl MountInfo {
    /// Attempts to find the `MountInfo` for the given `path`.
    pub fn for_path<P: AsRef<Path>>(path: P) -> Result<Option<Self>, String> {
        let system = SystemStat::new();
        let mounts = system
            .mounts()
            .map_err(|e| format!("Unable to enumerate mounts: {:?}", e))?;

        let mut mounts = mounts
            .iter()
            .filter_map(|drive| {
                let mount_path = Path::new(&drive.fs_mounted_on);
                let num_components = mount_path.iter().count();

                Some((drive, mount_path, num_components))
                    .filter(|_| path.as_ref().starts_with(&mount_path))
            })
            .collect::<Vec<_>>();

        // Sort the list of mount points, such that the path with the most components is first.
        //
        // For example:
        //
        // ```
        // let mounts = ["/home/paul", "/home", "/"];
        // ```
        //
        // The intention here is to find the "closest" mount-point to `path`, such that
        // `/home/paul/file` matches `/home/paul`, not `/` or `/home`.
        mounts.sort_unstable_by(|(_, _, a), (_, _, b)| b.cmp(a));

        let disk_usage = mounts.first().map(|(drive, mount_path, _)| {
            let avail = drive.avail.as_u64();
            let total = drive.total.as_u64();
            let used = total.saturating_sub(avail);
            let mut used_pct = if total > 0 {
                used as f64 / total as f64
            } else {
                0.0
            } * 100.0;

            // Round to two decimals.
            used_pct = (used_pct * 100.00).round() / 100.00;

            Self {
                avail,
                total,
                used,
                used_pct,
                mounted_on: mount_path.into(),
            }
        });

        Ok(disk_usage)
    }
}

/// Reports information about a drive on the system the Lighthouse instance is running on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Drive {
    /// The filesystem name.
    pub filesystem: String,
    /// The amount of disk space available on the filesystem.
    pub avail: u64,
    /// The amount of disk space used on the filesystem. Equivalent to `total-avail`.
    pub used: u64,
    /// The percentage of disk space used on the filesystem. Equivalent to `(total-avail) / total`.
    pub used_pct: u64,
    /// The total amount of disk space on the filesystem.
    pub total: u64,
    /// The filesystem mount point.
    pub mounted_on: String,
}

impl Drive {
    pub fn observe() -> Result<Vec<Self>, String> {
        let system = SystemStat::new();
        Ok(system
            .mounts()
            .expect("Could not find mounts.")
            .into_iter()
            // filter out drives with zero total disk space
            .filter(|drive| drive.total.as_u64() != 0)
            .map(|drive| Drive {
                filesystem: drive.fs_mounted_from,
                avail: drive.avail.as_u64(),
                used: drive.total.as_u64() - drive.avail.as_u64(),
                used_pct: (((drive.total.0 as f64 - drive.avail.0 as f64) / drive.total.0 as f64)
                    * 100.0) as u64,
                total: drive.total.as_u64(),
                mounted_on: drive.fs_mounted_on,
            })
            .collect())
    }
}

/// Reports information about the network on the system the Lighthouse instance is running on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Network {
    /// Network metric for total received bytes across all network interfaces.
    pub rx_bytes: u64,
    /// Network metric for total received errors across all network interfaces.
    pub rx_errors: u64,
    /// Network metric for total received packets across all network interfaces.
    pub rx_packets: u64,
    /// Network metric for total transmitted bytes across all network interfaces.
    pub tx_bytes: u64,
    /// Network metric for total trasmitted errors across all network interfaces.
    pub tx_errors: u64,
    /// Network metric for total transmitted packets across all network interfaces.
    pub tx_packets: u64,
}

impl Network {
    pub fn observe() -> Result<Self, String> {
        let mut rx_bytes = 0;
        let mut rx_errors = 0;
        let mut rx_packets = 0;
        let mut tx_bytes = 0;
        let mut tx_errors = 0;
        let mut tx_packets = 0;

        let s = SystemInfo::new_all();
        s.get_networks().iter().for_each(|(_, network)| {
            rx_bytes += network.get_total_received();
            rx_errors += network.get_total_transmitted();
            rx_packets += network.get_total_packets_received();
            tx_bytes += network.get_total_packets_transmitted();
            tx_errors += network.get_total_errors_on_received();
            tx_packets += network.get_total_errors_on_transmitted();
        });

        Ok(Network {
            rx_bytes,
            rx_errors,
            rx_packets,
            tx_bytes,
            tx_errors,
            tx_packets,
        })
    }
}

/// Reports on the health of the Lighthouse instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// The pid of this process.
    pub pid: u32,
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
    /// Network statistics, totals across all network interfaces.
    pub network: Network,
    /// Filesystem information.
    pub chain_database: Option<MountInfo>,
    /// Filesystem information.
    pub freezer_database: Option<MountInfo>,
}

impl Health {
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    pub fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux and MacOS".into())
    }

    #[cfg(target_os = "linux")]
    pub fn observe() -> Result<Self, String> {
        let process =
            Process::current().map_err(|e| format!("Unable to get current process: {:?}", e))?;

        let process_mem = process
            .memory_info()
            .map_err(|e| format!("Unable to get process memory info: {:?}", e))?;

        let vm = psutil::memory::virtual_memory()
            .map_err(|e| format!("Unable to get virtual memory: {:?}", e))?;

        let loadavg =
            psutil::host::loadavg().map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        Ok(Self {
            pid: process.pid(),
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
            network: Network::observe()?,
            chain_database: MountInfo::for_path("/home/paul/.lighthouse/medalla/beacon/chain_db")?,
            freezer_database: MountInfo::for_path(
                "/home/paul/.lighthouse/medalla/beacon/freezer_db",
            )?,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn observe() -> Result<Self, String> {
        let process =
            Process::current().map_err(|e| format!("Unable to get current process: {:?}", e))?;

        let process_mem = process
            .memory_info()
            .map_err(|e| format!("Unable to get process memory info: {:?}", e))?;

        let vm = psutil::memory::virtual_memory()
            .map_err(|e| format!("Unable to get virtual memory: {:?}", e))?;

        let sys = SystemStat::new();

        let loadavg = sys
            .load_average()
            .map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        Ok(Self {
            pid: process.pid() as u32,
            pid_mem_resident_set_size: process_mem.rss(),
            pid_mem_virtual_memory_size: process_mem.vms(),
            sys_virt_mem_total: vm.total(),
            sys_virt_mem_available: vm.available(),
            sys_virt_mem_used: vm.used(),
            sys_virt_mem_free: vm.free(),
            sys_virt_mem_percent: vm.percent(),
            sys_loadavg_1: loadavg.one as f64,
            sys_loadavg_5: loadavg.five as f64,
            sys_loadavg_15: loadavg.fifteen as f64,
            network: Network::observe()?,
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

    /// `GET lighthouse/system`
    pub async fn get_lighthouse_system(&self) -> Result<GenericResponse<System>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("system");

        self.get(path).await
    }

    /// `GET lighthouse/system/health`
    pub async fn get_lighthouse_system_health(&self) -> Result<GenericResponse<Health>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("system")
            .push("health");

        self.get(path).await
    }

    /// `GET lighthouse/system/drives`
    pub async fn get_lighthouse_system_drives(&self) -> Result<GenericResponse<Vec<Drive>>, Error> {
        let mut path = self.server.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("system")
            .push("drives");

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

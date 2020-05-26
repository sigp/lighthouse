//! Collection of types for the /node HTTP
use procinfo::pid;
use psutil::process::Process;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::Slot;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
/// The current syncing status of the node.
pub struct SyncingStatus {
    /// The starting slot of sync.
    ///
    /// For a finalized sync, this is the start slot of the current finalized syncing
    /// chain.
    ///
    /// For head sync this is the last finalized slot.
    pub starting_slot: Slot,
    /// The current slot.
    pub current_slot: Slot,
    /// The highest known slot. For the current syncing chain.
    ///
    /// For a finalized sync, the target finalized slot.
    /// For head sync, this is the highest known slot of all head chains.
    pub highest_slot: Slot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
/// The response for the /node/syncing HTTP GET.
pub struct SyncingResponse {
    /// Is the node syncing.
    pub is_syncing: bool,
    /// The current sync status.
    pub sync_status: SyncingStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Reports on the health of the Lighthouse instance.
pub struct Health {
    /// The pid of this process.
    pid: u32,
    /// Threads opened by this process.
    pid_threads: i32,
    /// Total virtual memory size for this process.
    pid_mem_size: usize,
    /// Resident non-swapped memory for this process.
    pid_mem_resident: usize,
    /// Shared memory for this process.
    pid_mem_share: usize,
    /// Resident executable memory for this process.
    pid_mem_text: usize,
    /// Resident data and stack memory for this process.
    pid_mem_data: usize,
    /// Total virtual memory on the system
    sys_virt_mem_total: u64,
    /// Total virtual memory available for new processes.
    sys_virt_mem_available: u64,
    /// Total virtual memory used on the system
    sys_virt_mem_used: u64,
    /// Total virtual memory not used on the system
    sys_virt_mem_free: u64,
    /// Percentage of virtual memory used on the system
    sys_virt_mem_percent: f32,
    /// System load average over 1 minute.
    sys_loadavg_1: f64,
    /// System load average over 5 minutes.
    sys_loadavg_5: f64,
    /// System load average over 15 minutes.
    sys_loadavg_15: f64,
}

impl Health {
    pub fn observe() -> Result<Self, String> {
        let process =
            Process::current().map_err(|e| format!("Unable to get current process: {:?}", e))?;

        let statm = pid::statm_self().map_err(|e| format!("Unable to get statm: {:?}", e))?;
        let stat = pid::stat_self().map_err(|e| format!("Unable to get stat: {:?}", e))?;
        let vm = psutil::memory::virtual_memory()
            .map_err(|e| format!("Unable to get virtual memory: {:?}", e))?;
        let loadavg =
            psutil::host::loadavg().map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        Ok(Self {
            pid: process.pid().into(),
            pid_threads: stat.num_threads,
            pid_mem_size: statm.size,
            pid_mem_resident: statm.resident,
            pid_mem_share: statm.share,
            pid_mem_text: statm.text,
            pid_mem_data: statm.data,
            sys_virt_mem_total: vm.total().into(),
            sys_virt_mem_available: vm.available().into(),
            sys_virt_mem_used: vm.used().into(),
            sys_virt_mem_free: vm.free().into(),
            sys_virt_mem_percent: vm.percent().into(),
            sys_loadavg_1: loadavg.one.into(),
            sys_loadavg_5: loadavg.five.into(),
            sys_loadavg_15: loadavg.fifteen.into(),
        })
    }
}

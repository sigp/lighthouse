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
            pid: process.pid().into(),
            pid_num_threads: stat.num_threads,
            pid_mem_resident_set_size: process_mem.rss().into(),
            pid_mem_virtual_memory_size: process_mem.vms().into(),
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

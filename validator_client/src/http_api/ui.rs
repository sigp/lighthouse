use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use sysinfo::{CpuExt, DiskExt, System, SystemExt};

/// System related health, specific to the UI.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SystemHealth {
    /// Total memory of the system.
    pub total_memory: u64,
    /// Total free memory available to the system.
    pub free_memory: u64,
    /// Total used memory.
    pub used_memory: u64,

    /// System load average over 1 minute.
    pub sys_loadavg_1: f64,
    /// System load average over 5 minutes.
    pub sys_loadavg_5: f64,
    /// System load average over 15 minutes.
    pub sys_loadavg_15: f64,

    /// Total cpu cores.
    pub cpu_cores: usize,
    /// Total cpu threads.
    pub cpu_threads: usize,
    /// The global cpu frequency.
    pub global_cpu_frequency: f32,

    /// Total capacity of disk.
    pub disk_bytes_total: u64,
    /// Free space in disk.
    pub disk_bytes_free: u64,

    /// System uptime.
    pub system_uptime: u64,
    /// Application uptime.
    pub app_uptime: u64,
    /// The System name
    pub system_name: String,
    /// Kernel version
    pub kernel_version: String,
    /// OS version
    pub os_version: String,
    /// Hostname
    pub host_name: String,
}

impl SystemHealth {
    /// Populates the system health.
    pub fn observe(sysinfo: Arc<RwLock<System>>, app_uptime: u64) -> Self {
        let sysinfo = sysinfo.read();
        let loadavg = sysinfo.load_average();

        let cpus = sysinfo.cpus();

        let disks = sysinfo.disks();

        let system_uptime = sysinfo.uptime();

        // Helper functions to extract specific data

        // Find the root fs and report this
        let (disk_bytes_total, disk_bytes_free) = {
            let individual_disk = disks
                .iter()
                .find(|disk| {
                    disk.mount_point() == Path::new("/")
                        || disk.mount_point() == Path::new("C:\\")
                        || disk.mount_point() == Path::new("/System/Volumes/Data")
                })
                .map(|disk| (disk.total_space(), disk.available_space()));

            match individual_disk {
                Some(v) => v,
                None => {
                    // If we can't find a known partition, just add them all up
                    disks.iter().fold((0, 0), |mut current_sizes, disk| {
                        current_sizes.0 += disk.total_space();
                        current_sizes.1 += disk.available_space();
                        current_sizes
                    })
                }
            }
        };

        // Attempt to get the clock speed from the name of the CPU
        let cpu_frequency_from_name = cpus.iter().next().and_then(|cpu| {
            cpu.brand()
                .split_once("GHz")
                .and_then(|(result, _)| result.trim().rsplit_once(' '))
                .and_then(|(_, result)| result.parse::<f32>().ok())
        });

        let global_cpu_frequency = match cpu_frequency_from_name {
            Some(freq) => freq,
            None => {
                // Get the frequency from average measured frequencies
                let global_cpu_frequency: f32 =
                    cpus.iter().map(|cpu| cpu.frequency()).sum::<u64>() as f32 / cpus.len() as f32;
                // Shift to ghz to 1dp
                (global_cpu_frequency / 100.0).round() / 10.0
            }
        };

        Self {
            total_memory: sysinfo.total_memory(),
            free_memory: sysinfo.free_memory(),
            used_memory: sysinfo.used_memory(),
            sys_loadavg_1: loadavg.one,
            sys_loadavg_5: loadavg.five,
            sys_loadavg_15: loadavg.fifteen,
            cpu_cores: sysinfo.physical_core_count().unwrap_or(0),
            cpu_threads: cpus.len(),
            global_cpu_frequency,
            disk_bytes_total,
            disk_bytes_free,
            system_uptime,
            app_uptime,
            system_name: sysinfo.name().unwrap_or_else(|| String::from("")),
            kernel_version: sysinfo.kernel_version().unwrap_or_else(|| "".into()),
            os_version: sysinfo.long_os_version().unwrap_or_else(|| "".into()),
            host_name: sysinfo.host_name().unwrap_or_else(|| "".into()),
        }
    }
}

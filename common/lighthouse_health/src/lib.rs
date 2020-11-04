use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use sysinfo::{NetworkExt, NetworksExt, System as SystemInfo, SystemExt};
use systemstat::{Platform, System as SystemStat};

#[cfg(target_os = "macos")]
use psutil::process::Process;
#[cfg(target_os = "linux")]
use psutil::process::Process;

const MB: u64 = 1_000_000;
const GB: u64 = 1_000_000_000;
const MIN_SAFE_DB_SIZE: u64 = 1 * GB;
const CHAIN_DB_REQ_SIZE: u64 = 100 * GB;
const FREEZER_DB_REQ_SIZE: u64 = 20 * GB;
const TOTAL_REQ_SIZE: u64 = CHAIN_DB_REQ_SIZE + FREEZER_DB_REQ_SIZE;

const LOAD_AVG_PCT_WARN: f64 = 85.0;
const LOAD_AVG_PCT_ERROR: f64 = 100.0;

const SAFE_PEER_COUNT: usize = 4;
const EXPECTED_PEER_COUNT: usize = 55; // TODO: get this dynamically.

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Status {
    status: String,
    message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatusGauge {
    status: String,
    message: String,
    gauge_pct: f64,
}

pub struct Eth1SyncInfo {
    pub eth1_node_sync_status_percentage: f64,
    pub lighthouse_is_cached_and_ready: bool,
}

impl Status {
    pub fn error(message: String) -> Self {
        Self {
            status: "error".to_string(),
            message,
        }
    }

    pub fn warn(message: String) -> Self {
        Self {
            status: "warn".to_string(),
            message,
        }
    }

    pub fn ok(message: String) -> Self {
        Self {
            status: "ok".to_string(),
            message,
        }
    }

    pub fn gauge(self, gauge_pct: f64) -> StatusGauge {
        StatusGauge {
            status: self.status,
            message: self.message,
            gauge_pct,
        }
    }
}

/// The two paths to the two core Lighthouse databases.
#[derive(Debug, Clone, PartialEq)]
pub struct DBPaths {
    pub chain_db: PathBuf,
    pub freezer_db: PathBuf,
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
            let used_pct = if total > 0 {
                used as f64 / total as f64
            } else {
                0.0
            } * 100.0;

            Self {
                avail,
                total,
                used,
                used_pct: round(used_pct, 2),
                mounted_on: mount_path.into(),
            }
        });

        Ok(disk_usage)
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
pub struct CommonHealth {
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
}

impl CommonHealth {
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
        })
    }
}

/// Reports on the health of the Lighthouse instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BeaconHealth {
    /// A rough status of the CPU usage.
    pub cpu_status: StatusGauge,
    /// RAM usage.
    pub memory_status: StatusGauge,
    /// Info about the eth1 chain.
    pub eth1_status: StatusGauge,
    /// Info about the libp2p network.
    pub p2p_status: Option<StatusGauge>,
    /// The combined status for the chain and freezer databases.
    pub database_status: Option<StatusGauge>,
    #[serde(flatten)]
    pub common: CommonHealth,
    /// Network statistics, totals across all network interfaces.
    pub network: Network,
    /// Filesystem information.
    pub chain_database: Option<MountInfo>,
    /// Filesystem information.
    pub freezer_database: Option<MountInfo>,
}

impl BeaconHealth {
    pub fn observe(
        db_paths: &DBPaths,
        peer_count_opt: Option<usize>,
        eth1_opt: Option<Eth1SyncInfo>,
    ) -> Result<Self, String> {
        let common = CommonHealth::observe()?;
        let cpu_status = cpu_status(&common);
        let memory_status = memory_status(&common);
        let eth1_status = eth1_status(eth1_opt);
        let p2p_status = peer_count_opt.map(p2p_status);

        let chain_database = MountInfo::for_path(&db_paths.chain_db)?;
        let freezer_database = MountInfo::for_path(&db_paths.freezer_db)?;

        let database_status = chain_database
            .as_ref()
            .and_then(|chain| Some((chain, freezer_database.as_ref()?)))
            .map(|(chain, freezer)| database_status(chain, freezer));

        Ok(Self {
            cpu_status,
            memory_status,
            eth1_status,
            p2p_status,
            database_status,
            common: CommonHealth::observe()?,
            network: Network::observe()?,
            chain_database: MountInfo::for_path(&db_paths.chain_db)?,
            freezer_database: MountInfo::for_path(&db_paths.freezer_db)?,
        })
    }
}

fn cpu_status(health: &CommonHealth) -> StatusGauge {
    // Disallow 0 CPUs to avoid a divide-by-zero.
    //
    // Note: we're using one library to detect loadavg and another to detect CPU count. I can
    // imagine this might cause issues on some platforms, but I don't know how to resolve it.
    let num_cpus = std::cmp::max(1, num_cpus::get()) as f64;
    let pct = round(health.sys_loadavg_5 as f64 / num_cpus, 2);

    if pct > LOAD_AVG_PCT_ERROR {
        Status::error("CPU is overloaded.".to_string()).gauge(pct)
    } else if pct > LOAD_AVG_PCT_WARN {
        Status::warn("CPU has high load.".to_string()).gauge(pct)
    } else {
        Status::ok(format!("CPU below {:0}%", LOAD_AVG_PCT_WARN)).gauge(pct)
    }
}

const MEMORY_AVAILABLE_ERROR: u64 = 512 * MB;
const MEMORY_AVAILABLE_WARN: u64 = 1 * GB;
const MEMORY_RECOMMENDED_TOTAL: u64 = 8 * GB;

fn memory_status(health: &CommonHealth) -> StatusGauge {
    let avail = health.sys_virt_mem_available;
    let total = health.sys_virt_mem_total;

    let status = if avail < MEMORY_AVAILABLE_ERROR {
        Status::error(format!(
            "Available system memory critically low: {} MB.",
            avail / MB
        ))
    } else if avail < MEMORY_AVAILABLE_WARN {
        Status::warn(format!(
            "Available system memory is low: {} GB.",
            avail / GB
        ))
    } else if total < MEMORY_RECOMMENDED_TOTAL {
        Status::warn(format!(
            "Total system memory {} GB is less than the recommended {} GB.",
            total / GB,
            MEMORY_RECOMMENDED_TOTAL / GB
        ))
    } else {
        Status::ok(format!("{} GB available memory", avail / GB))
    };

    status.gauge(round(health.sys_virt_mem_percent as f64, 2))
}

fn eth1_status(eth1_opt: Option<Eth1SyncInfo>) -> StatusGauge {
    if let Some(eth1) = eth1_opt {
        let ready = eth1.lighthouse_is_cached_and_ready;
        let pct = round(eth1.eth1_node_sync_status_percentage, 2);

        if ready {
            if pct == 100.0 {
                Status::ok("Eth1 is fully synced.".to_string())
            } else {
                Status::warn(format!("Eth1 is adequately synced at {}%.", pct))
            }
        } else {
            if pct == 100.0 {
                Status::warn("Eth1 is fully synced but caches are still being built.".to_string())
            } else {
                Status::warn(format!(
                    "Eth1 is not adequately synced. Estimated progress: {}%.",
                    pct,
                ))
            }
        }
        .gauge(pct)
    } else {
        Status::error(
            "Eth1 sync is disabled, use the --eth1 CLI flag to enable. Eth1 is only \
            required for validators."
                .to_string(),
        )
        .gauge(0.0)
    }
}

fn p2p_status(peer_count: usize) -> StatusGauge {
    let peer_count = std::cmp::min(peer_count, EXPECTED_PEER_COUNT);
    let pct = round((peer_count as f64 / EXPECTED_PEER_COUNT as f64) * 100.0, 2);

    if peer_count == 0 {
        Status::error("No connected peers.".to_string())
    } else if peer_count < SAFE_PEER_COUNT {
        Status::warn(format!("Low peer count ({}).", peer_count))
    } else {
        Status::warn(format!("Peer count sufficient ({}).", peer_count))
    }
    .gauge(pct)
}

fn database_status(chain: &MountInfo, freezer: &MountInfo) -> StatusGauge {
    if chain.mounted_on == freezer.mounted_on {
        status_for_disk(&chain.mounted_on, chain.avail, TOTAL_REQ_SIZE).gauge(chain.used_pct)
    } else {
        match (
            chain.avail.cmp(&CHAIN_DB_REQ_SIZE),
            freezer.avail.cmp(&FREEZER_DB_REQ_SIZE),
        ) {
            (Ordering::Less, Ordering::Less) => {
                // Indicate using the lowest percentage.
                let pct = if chain.used_pct > freezer.used_pct {
                    freezer.used_pct
                } else {
                    chain.used_pct
                };

                Status::error(format!(
                    "Insufficient size for {} and {}; {} and {} additional GB recommended,
                respectively.",
                    chain.mounted_on.to_string_lossy(),
                    freezer.mounted_on.to_string_lossy(),
                    CHAIN_DB_REQ_SIZE - chain.avail,
                    FREEZER_DB_REQ_SIZE - freezer.avail
                ))
                .gauge(pct)
            }
            (Ordering::Less, _) => {
                status_for_disk(&chain.mounted_on, chain.avail, CHAIN_DB_REQ_SIZE)
                    .gauge(chain.used_pct)
            }
            (_, Ordering::Less) => {
                status_for_disk(&freezer.mounted_on, freezer.avail, FREEZER_DB_REQ_SIZE)
                    .gauge(freezer.used_pct)
            }
            _ => Status::ok(format!(
                "{} and {} exceed the recommended capacity.",
                chain.mounted_on.to_string_lossy(),
                freezer.mounted_on.to_string_lossy()
            ))
            .gauge(100.0),
        }
    }
}

fn status_for_disk(mount: &PathBuf, avail: u64, recommended: u64) -> Status {
    if avail < MIN_SAFE_DB_SIZE {
        Status::error(format!(
            "Critically low disk space on {}; {} MB available.",
            mount.to_string_lossy(),
            avail / MB
        ))
    } else if recommended > avail {
        Status::warn(format!(
            "Low disk space on {}; {} GB recommended but {} GB available.",
            mount.to_string_lossy(),
            recommended / GB,
            avail / GB
        ))
    } else {
        Status::ok(format!(
            "{} has sufficient capacity.",
            mount.to_string_lossy()
        ))
    }
}

fn round(x: f64, decimals: i32) -> f64 {
    let precision = 10.0_f64.powi(decimals);
    (x * precision).round() / precision
}

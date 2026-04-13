use eth2::lighthouse::{Health, ProcessHealth, SystemHealth};

#[cfg(target_os = "linux")]
use procfs::{Current, CurrentSI, process::Process};

pub trait Observe: Sized {
    fn observe() -> Result<Self, String>;
}

impl Observe for Health {
    #[cfg(not(target_os = "linux"))]
    fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn observe() -> Result<Self, String> {
        Ok(Self {
            process: ProcessHealth::observe()?,
            system: SystemHealth::observe()?,
        })
    }
}

impl Observe for SystemHealth {
    #[cfg(not(target_os = "linux"))]
    fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn observe() -> Result<Self, String> {
        let meminfo =
            procfs::Meminfo::current().map_err(|e| format!("Unable to get meminfo: {:?}", e))?;

        let mem_total = meminfo.mem_total;
        let mem_free = meminfo.mem_free;
        let mem_available = meminfo.mem_available.unwrap_or(mem_free);
        // Match `psutil` by calculating cached as cached + s_reclaimable.
        let mem_cached = meminfo.cached + meminfo.s_reclaimable.unwrap_or(0);
        let mem_buffers = meminfo.buffers;
        // Match `psutil` by calculating used as total - free - buffers - cached.
        let mem_used = mem_total.saturating_sub(mem_free + mem_buffers + mem_cached);
        let mem_percent = if mem_total > 0 {
            (mem_total.saturating_sub(mem_available) as f32 / mem_total as f32) * 100.0
        } else {
            0.0
        };

        let loadavg = procfs::LoadAverage::current()
            .map_err(|e| format!("Unable to get loadavg: {:?}", e))?;

        let kernel_stats = procfs::KernelStats::current()
            .map_err(|e| format!("Unable to get kernel stats: {:?}", e))?;

        let cpu_total = &kernel_stats.total;
        let ticks_per_second = procfs::ticks_per_second();
        let user_seconds_total = cpu_total.user / ticks_per_second;
        let system_seconds_total = cpu_total.system / ticks_per_second;
        let iowait_ticks = cpu_total.iowait.unwrap_or(0);
        // Match `psutil` by calculating idle as idle + iowait
        let idle_seconds_total = (cpu_total.idle + iowait_ticks) / ticks_per_second;
        let iowait_seconds_total = iowait_ticks / ticks_per_second;

        // Total CPU time (user + nice + system + idle + iowait + irq + softirq)
        let cpu_time_total = (cpu_total.user
            + cpu_total.nice
            + cpu_total.system
            + cpu_total.idle
            + cpu_total.iowait.unwrap_or(0)
            + cpu_total.irq.unwrap_or(0)
            + cpu_total.softirq.unwrap_or(0))
            / ticks_per_second;

        let cpu_threads = kernel_stats.cpu_time.len() as u64;
        let cpu_cores = procfs::CpuInfo::current()
            .ok()
            .and_then(|info| {
                let cores: std::collections::HashSet<_> = (0..info.num_cores())
                    .filter_map(|i| {
                        Some((
                            info.get_field(i, "physical id")?.to_owned(),
                            info.get_field(i, "core id")?.to_owned(),
                        ))
                    })
                    .collect();
                if cores.is_empty() {
                    None
                } else {
                    cores.len().try_into().ok()
                }
            })
            .unwrap_or(cpu_threads);

        let disk_usage = nix::sys::statvfs::statvfs("/")
            .map_err(|e| format!("Unable to get disk usage: {:?}", e))?;
        let disk_total = disk_usage
            .blocks()
            .saturating_mul(disk_usage.fragment_size());
        // Match `psutil` by using blocks_available (f_bavail, available to unprivileged users)
        // rather than blocks_free (f_bfree, total free blocks including root-reserved).
        let disk_free = disk_usage
            .blocks_available()
            .saturating_mul(disk_usage.fragment_size());

        // Disk I/O from /proc/diskstats
        let diskstats =
            procfs::diskstats().map_err(|e| format!("Unable to get disk stats: {:?}", e))?;
        let (disk_reads, disk_writes) = diskstats
            .iter()
            .fold((0u64, 0u64), |(reads, writes), disk| {
                (reads + disk.reads, writes + disk.writes)
            });

        let net_dev =
            procfs::net::dev_status().map_err(|e| format!("Unable to get net dev: {:?}", e))?;
        let (net_recv, net_sent) = net_dev.values().fold((0u64, 0u64), |(recv, sent), iface| {
            (recv + iface.recv_bytes, sent + iface.sent_bytes)
        });

        let boot_time = kernel_stats.btime;

        Ok(Self {
            sys_virt_mem_total: mem_total,
            sys_virt_mem_available: mem_available,
            sys_virt_mem_used: mem_used,
            sys_virt_mem_free: mem_free,
            sys_virt_mem_cached: mem_cached,
            sys_virt_mem_buffers: mem_buffers,
            sys_virt_mem_percent: mem_percent,
            sys_loadavg_1: loadavg.one as f64,
            sys_loadavg_5: loadavg.five as f64,
            sys_loadavg_15: loadavg.fifteen as f64,
            cpu_cores,
            cpu_threads,
            system_seconds_total,
            cpu_time_total,
            user_seconds_total,
            iowait_seconds_total,
            idle_seconds_total,
            disk_node_bytes_total: disk_total,
            disk_node_bytes_free: disk_free,
            disk_node_reads_total: disk_reads,
            disk_node_writes_total: disk_writes,
            network_node_bytes_total_received: net_recv,
            network_node_bytes_total_transmit: net_sent,
            misc_node_boot_ts_seconds: boot_time,
            misc_os: std::env::consts::OS.to_string(),
        })
    }
}

impl Observe for ProcessHealth {
    #[cfg(not(target_os = "linux"))]
    fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn observe() -> Result<Self, String> {
        let me = Process::myself().map_err(|e| format!("Unable to get process: {:?}", e))?;

        let stat = me
            .stat()
            .map_err(|e| format!("Unable to get stat: {:?}", e))?;

        let statm = me
            .statm()
            .map_err(|e| format!("Unable to get statm: {:?}", e))?;

        let page_size = procfs::page_size();

        // Match `psutil` by calculating process time as utime + stime + cutime + cstime (user + system + children)
        // Note that `busy == (user + system)`.
        let ticks_per_second = procfs::ticks_per_second();
        let cutime = u64::try_from(stat.cutime).unwrap_or(0);
        let cstime = u64::try_from(stat.cstime).unwrap_or(0);
        let process_seconds = (stat.utime + stat.stime + cutime + cstime) / ticks_per_second;

        Ok(Self {
            pid: stat.pid as u32,
            pid_num_threads: stat.num_threads,
            pid_mem_resident_set_size: statm.resident * page_size,
            pid_mem_virtual_memory_size: statm.size * page_size,
            pid_mem_shared_memory_size: statm.shared * page_size,
            pid_process_seconds_total: process_seconds,
        })
    }
}

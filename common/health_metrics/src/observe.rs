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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Tolerance for system memory metrics (available, free, cached, buffers, used).
    /// Memory state can change between reads due to system activity.
    const SYSTEM_MEMORY_TOLERANCE_BYTES: u64 = 16 * 1024 * 1024; // 16MB

    /// Tolerance for memory percentage calculation.
    /// Accounts for floating point precision differences.
    const MEMORY_PERCENT_TOLERANCE: f32 = 0.01; // 0.01%

    /// Tolerance for load average values.
    /// Accounts for f32 to f64 conversion precision loss.
    const LOAD_AVERAGE_TOLERANCE: f64 = 0.0001;

    /// Tolerance for CPU time metrics (user, system, idle, iowait, total).
    /// Time passes between our read and psutil's read.
    const CPU_TIME_TOLERANCE_SECS: u64 = 1;

    /// Tolerance for disk free space.
    /// Disk activity can occur between reads.
    const DISK_FREE_TOLERANCE_BYTES: u64 = 512 * 1024; // 512KB

    /// Tolerance for disk I/O operation counts.
    /// Disk activity can occur between reads.
    const DISK_IO_TOLERANCE_OPS: u64 = 10;

    /// Tolerance for network I/O byte counts.
    /// Network activity can occur between reads.
    const NETWORK_IO_TOLERANCE_BYTES: u64 = 8 * 1024; // 8KB

    /// Tolerance for process memory metrics (RSS, VMS, shared).
    /// Process allocations can occur between reads.
    const PROCESS_MEMORY_TOLERANCE_BYTES: u64 = 1024 * 1024; // 1MB

    /// Helper to check if two u64 values are within a tolerance.
    /// Used for values that can change between measurements (memory, I/O counters).
    fn within_tolerance(ours: u64, theirs: u64, tolerance_bytes: u64) -> bool {
        ours.abs_diff(theirs) <= tolerance_bytes
    }

    /// Compare the new procfs-based implementation against psutil to verify
    /// we get equivalent values from the same underlying /proc data source.
    ///
    /// Note: Some values (memory, I/O counters) can change between when we read
    /// our values and when psutil reads its values, so we allow small tolerances.
    #[test]
    fn compare_system_health_with_psutil() {
        use psutil::cpu::os::linux::CpuTimesExt;
        use psutil::memory::os::linux::VirtualMemoryExt;

        // Get values from our new implementation
        let our_health = SystemHealth::observe().expect("Failed to observe SystemHealth");

        // Get values from psutil for comparison
        let psutil_vm = psutil::memory::virtual_memory().expect("psutil virtual_memory failed");
        let psutil_loadavg = psutil::host::loadavg().expect("psutil loadavg failed");
        let psutil_cpu = psutil::cpu::cpu_times().expect("psutil cpu_times failed");
        let psutil_disk_usage = psutil::disk::disk_usage("/").expect("psutil disk_usage failed");
        let psutil_disk_io = psutil::disk::DiskIoCountersCollector::default()
            .disk_io_counters()
            .expect("psutil disk_io_counters failed");
        let psutil_net_io = psutil::network::NetIoCountersCollector::default()
            .net_io_counters()
            .expect("psutil net_io_counters failed");
        let psutil_boot_time = psutil::host::boot_time()
            .expect("psutil boot_time failed")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("boot time before epoch")
            .as_secs();

        // Memory stats (same source: /proc/meminfo)
        // Total should be identical (doesn't change)
        assert_eq!(
            our_health.sys_virt_mem_total,
            psutil_vm.total(),
            "mem_total mismatch"
        );

        // These can change between reads
        assert!(
            within_tolerance(
                our_health.sys_virt_mem_available,
                psutil_vm.available(),
                SYSTEM_MEMORY_TOLERANCE_BYTES
            ),
            "mem_available mismatch: ours={}, psutil={}, diff={}",
            our_health.sys_virt_mem_available,
            psutil_vm.available(),
            our_health
                .sys_virt_mem_available
                .abs_diff(psutil_vm.available())
        );
        assert!(
            within_tolerance(
                our_health.sys_virt_mem_free,
                psutil_vm.free(),
                SYSTEM_MEMORY_TOLERANCE_BYTES
            ),
            "mem_free mismatch: ours={}, psutil={}, diff={}",
            our_health.sys_virt_mem_free,
            psutil_vm.free(),
            our_health.sys_virt_mem_free.abs_diff(psutil_vm.free())
        );
        assert!(
            within_tolerance(
                our_health.sys_virt_mem_cached,
                psutil_vm.cached(),
                SYSTEM_MEMORY_TOLERANCE_BYTES
            ),
            "mem_cached mismatch: ours={}, psutil={}, diff={}",
            our_health.sys_virt_mem_cached,
            psutil_vm.cached(),
            our_health.sys_virt_mem_cached.abs_diff(psutil_vm.cached())
        );
        assert!(
            within_tolerance(
                our_health.sys_virt_mem_buffers,
                psutil_vm.buffers(),
                SYSTEM_MEMORY_TOLERANCE_BYTES
            ),
            "mem_buffers mismatch: ours={}, psutil={}, diff={}",
            our_health.sys_virt_mem_buffers,
            psutil_vm.buffers(),
            our_health
                .sys_virt_mem_buffers
                .abs_diff(psutil_vm.buffers())
        );
        assert!(
            within_tolerance(
                our_health.sys_virt_mem_used,
                psutil_vm.used(),
                SYSTEM_MEMORY_TOLERANCE_BYTES
            ),
            "mem_used mismatch: ours={}, psutil={}, diff={}",
            our_health.sys_virt_mem_used,
            psutil_vm.used(),
            our_health.sys_virt_mem_used.abs_diff(psutil_vm.used())
        );
        assert!(
            (our_health.sys_virt_mem_percent - psutil_vm.percent()).abs()
                < MEMORY_PERCENT_TOLERANCE,
            "mem_percent mismatch: ours={}, psutil={}",
            our_health.sys_virt_mem_percent,
            psutil_vm.percent()
        );

        // Load averages (same source: /proc/loadavg)
        assert!(
            (our_health.sys_loadavg_1 - psutil_loadavg.one).abs() < LOAD_AVERAGE_TOLERANCE,
            "loadavg_1 mismatch: ours={}, psutil={}",
            our_health.sys_loadavg_1,
            psutil_loadavg.one
        );
        assert!(
            (our_health.sys_loadavg_5 - psutil_loadavg.five).abs() < LOAD_AVERAGE_TOLERANCE,
            "loadavg_5 mismatch: ours={}, psutil={}",
            our_health.sys_loadavg_5,
            psutil_loadavg.five
        );
        assert!(
            (our_health.sys_loadavg_15 - psutil_loadavg.fifteen).abs() < LOAD_AVERAGE_TOLERANCE,
            "loadavg_15 mismatch: ours={}, psutil={}",
            our_health.sys_loadavg_15,
            psutil_loadavg.fifteen
        );

        // CPU times (same source: /proc/stat)
        assert!(
            our_health
                .system_seconds_total
                .abs_diff(psutil_cpu.system().as_secs())
                <= CPU_TIME_TOLERANCE_SECS,
            "system_seconds mismatch: ours={}, psutil={}",
            our_health.system_seconds_total,
            psutil_cpu.system().as_secs()
        );
        assert!(
            our_health
                .user_seconds_total
                .abs_diff(psutil_cpu.user().as_secs())
                <= CPU_TIME_TOLERANCE_SECS,
            "user_seconds mismatch: ours={}, psutil={}",
            our_health.user_seconds_total,
            psutil_cpu.user().as_secs()
        );
        assert!(
            our_health
                .idle_seconds_total
                .abs_diff(psutil_cpu.idle().as_secs())
                <= CPU_TIME_TOLERANCE_SECS,
            "idle_seconds mismatch: ours={}, psutil={}",
            our_health.idle_seconds_total,
            psutil_cpu.idle().as_secs()
        );
        assert!(
            our_health
                .iowait_seconds_total
                .abs_diff(psutil_cpu.iowait().as_secs())
                <= CPU_TIME_TOLERANCE_SECS,
            "iowait_seconds mismatch: ours={}, psutil={}",
            our_health.iowait_seconds_total,
            psutil_cpu.iowait().as_secs()
        );
        assert!(
            our_health
                .cpu_time_total
                .abs_diff(psutil_cpu.total().as_secs())
                <= CPU_TIME_TOLERANCE_SECS,
            "cpu_time_total mismatch: ours={}, psutil={}",
            our_health.cpu_time_total,
            psutil_cpu.total().as_secs()
        );

        // CPU cores/threads (same source: /proc/cpuinfo, /proc/stat, sysconf)
        assert_eq!(
            our_health.cpu_threads,
            psutil::cpu::cpu_count(),
            "cpu_threads mismatch"
        );
        assert_eq!(
            our_health.cpu_cores,
            psutil::cpu::cpu_count_physical(),
            "cpu_cores mismatch"
        );

        // Disk usage should be identical (both use statvfs)
        // Total shouldn't change, free might change slightly
        assert_eq!(
            our_health.disk_node_bytes_total,
            psutil_disk_usage.total(),
            "disk_total mismatch"
        );
        assert!(
            within_tolerance(
                our_health.disk_node_bytes_free,
                psutil_disk_usage.free(),
                DISK_FREE_TOLERANCE_BYTES
            ),
            "disk_free mismatch: ours={}, psutil={}, diff={}",
            our_health.disk_node_bytes_free,
            psutil_disk_usage.free(),
            our_health
                .disk_node_bytes_free
                .abs_diff(psutil_disk_usage.free())
        );

        // Disk I/O (same source: /proc/diskstats)
        assert!(
            within_tolerance(
                our_health.disk_node_reads_total,
                psutil_disk_io.read_count(),
                DISK_IO_TOLERANCE_OPS
            ),
            "disk_reads mismatch: ours={}, psutil={}, diff={}",
            our_health.disk_node_reads_total,
            psutil_disk_io.read_count(),
            our_health
                .disk_node_reads_total
                .abs_diff(psutil_disk_io.read_count())
        );
        assert!(
            within_tolerance(
                our_health.disk_node_writes_total,
                psutil_disk_io.write_count(),
                DISK_IO_TOLERANCE_OPS
            ),
            "disk_writes mismatch: ours={}, psutil={}, diff={}",
            our_health.disk_node_writes_total,
            psutil_disk_io.write_count(),
            our_health
                .disk_node_writes_total
                .abs_diff(psutil_disk_io.write_count())
        );

        // Network I/O (same source: /proc/net/dev)
        assert!(
            within_tolerance(
                our_health.network_node_bytes_total_received,
                psutil_net_io.bytes_recv(),
                NETWORK_IO_TOLERANCE_BYTES
            ),
            "net_recv mismatch: ours={}, psutil={}, diff={}",
            our_health.network_node_bytes_total_received,
            psutil_net_io.bytes_recv(),
            our_health
                .network_node_bytes_total_received
                .abs_diff(psutil_net_io.bytes_recv())
        );
        assert!(
            within_tolerance(
                our_health.network_node_bytes_total_transmit,
                psutil_net_io.bytes_sent(),
                NETWORK_IO_TOLERANCE_BYTES
            ),
            "net_sent mismatch: ours={}, psutil={}, diff={}",
            our_health.network_node_bytes_total_transmit,
            psutil_net_io.bytes_sent(),
            our_health
                .network_node_bytes_total_transmit
                .abs_diff(psutil_net_io.bytes_sent())
        );

        // Boot time - should be identical (same source: /proc/stat btime)
        assert_eq!(
            our_health.misc_node_boot_ts_seconds, psutil_boot_time,
            "boot_time mismatch"
        );

        println!("All SystemHealth values match between procfs and psutil!");
    }

    /// Compare process health metrics
    #[test]
    fn compare_process_health_with_psutil() {
        use psutil::process::Process as PsutilProcess;

        // Get values from our new implementation
        let our_health = ProcessHealth::observe().expect("Failed to observe ProcessHealth");

        // Get values from psutil for comparison
        let psutil_process = PsutilProcess::current().expect("psutil current process failed");
        let psutil_mem = psutil_process
            .memory_info()
            .expect("psutil memory_info failed");
        let psutil_cpu_times = psutil_process.cpu_times().expect("psutil cpu_times failed");

        // PID should match
        assert_eq!(our_health.pid, psutil_process.pid(), "pid mismatch");

        // Memory stats (same source: /proc/[pid]/statm)
        assert!(
            within_tolerance(
                our_health.pid_mem_resident_set_size,
                psutil_mem.rss(),
                PROCESS_MEMORY_TOLERANCE_BYTES
            ),
            "rss mismatch: ours={}, psutil={}, diff={}",
            our_health.pid_mem_resident_set_size,
            psutil_mem.rss(),
            our_health
                .pid_mem_resident_set_size
                .abs_diff(psutil_mem.rss())
        );
        assert!(
            within_tolerance(
                our_health.pid_mem_virtual_memory_size,
                psutil_mem.vms(),
                PROCESS_MEMORY_TOLERANCE_BYTES
            ),
            "vms mismatch: ours={}, psutil={}, diff={}",
            our_health.pid_mem_virtual_memory_size,
            psutil_mem.vms(),
            our_health
                .pid_mem_virtual_memory_size
                .abs_diff(psutil_mem.vms())
        );
        assert!(
            within_tolerance(
                our_health.pid_mem_shared_memory_size,
                psutil_mem.shared(),
                PROCESS_MEMORY_TOLERANCE_BYTES
            ),
            "shared mismatch: ours={}, psutil={}, diff={}",
            our_health.pid_mem_shared_memory_size,
            psutil_mem.shared(),
            our_health
                .pid_mem_shared_memory_size
                .abs_diff(psutil_mem.shared())
        );

        // Process CPU time
        let psutil_total_seconds = psutil_cpu_times.busy().as_secs()
            + psutil_cpu_times.children_user().as_secs()
            + psutil_cpu_times.children_system().as_secs();

        assert_eq!(
            our_health.pid_process_seconds_total, psutil_total_seconds,
            "process_seconds mismatch: ours={}, psutil={}",
            our_health.pid_process_seconds_total, psutil_total_seconds
        );

        println!("All ProcessHealth values match between procfs and psutil!");
    }
}

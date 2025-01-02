use eth2::lighthouse::{Health, ProcessHealth, SystemHealth};

#[cfg(target_os = "linux")]
use {
    psutil::cpu::os::linux::CpuTimesExt, psutil::memory::os::linux::VirtualMemoryExt,
    psutil::process::Process,
};

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

impl Observe for ProcessHealth {
    #[cfg(not(target_os = "linux"))]
    fn observe() -> Result<Self, String> {
        Err("Health is only available on Linux".into())
    }

    #[cfg(target_os = "linux")]
    fn observe() -> Result<Self, String> {
        let process =
            Process::current().map_err(|e| format!("Unable to get current process: {:?}", e))?;

        let process_mem = process
            .memory_info()
            .map_err(|e| format!("Unable to get process memory info: {:?}", e))?;

        let me = procfs::process::Process::myself()
            .map_err(|e| format!("Unable to get process: {:?}", e))?;
        let stat = me
            .stat()
            .map_err(|e| format!("Unable to get stat: {:?}", e))?;

        let process_times = process
            .cpu_times()
            .map_err(|e| format!("Unable to get process cpu times : {:?}", e))?;

        Ok(Self {
            pid: process.pid(),
            pid_num_threads: stat.num_threads,
            pid_mem_resident_set_size: process_mem.rss(),
            pid_mem_virtual_memory_size: process_mem.vms(),
            pid_mem_shared_memory_size: process_mem.shared(),
            pid_process_seconds_total: process_times.busy().as_secs()
                + process_times.children_system().as_secs()
                + process_times.children_system().as_secs(),
        })
    }
}

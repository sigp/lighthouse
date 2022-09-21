use serde::{Deserialize, Serialize};
use systemstat::{saturating_sub_bytes, Platform, System};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SystemHealth {
    // cpu
    load_avg_one: f32,
    load_avg_five: f32,
    load_avg_fifteen: f32,
    cpu_temp: f32,

    // memory
    mem_total: u64,
    mem_used: u64,
    mem_free: u64,

    // disk
    root_fs_size: u64,
    root_fs_avail: u64,

    // network
    // TODO: Have to select which networks to broadcast
    /*
    network_name: String,
    network_addr: IpAddr,
    network_stats_up: usize,
    network_stats_down: usize,
    */
    // uptime
    uptime: usize,
}

impl SystemHealth {
    pub fn observe() -> Result<Self, String> {
        let sys = System::new();

        let (load_avg_one, load_avg_five, load_avg_fifteen) = match sys.load_average() {
            Ok(loadavg) => (loadavg.one, loadavg.five, loadavg.fifteen),
            Err(_) => (0f32, 0f32, 0f32),
        };

        let (mem_total, mem_used, mem_free) = match sys.memory() {
            Ok(mem) => (
                mem.total.as_u64(),
                saturating_sub_bytes(mem.total, mem.free).as_u64(),
                mem.free.as_u64(),
            ),
            Err(_) => (0u64, 0, 0),
        };

        let (root_fs_size, root_fs_avail) = match sys.mount_at("/") {
            Ok(mount) => (mount.total.as_u64(), mount.avail.as_u64()),
            Err(_) => (0, 0),
        };

        let uptime = sys
            .uptime()
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs() as usize;

        let cpu_temp = sys.cpu_temp().unwrap_or(0f32);

        Ok(SystemHealth {
            load_avg_one,
            load_avg_five,
            load_avg_fifteen,
            cpu_temp,
            mem_total,
            mem_used,
            mem_free,
            root_fs_size,
            root_fs_avail,
            uptime,
        })
    }
}

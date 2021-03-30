use eth2::lighthouse::Health;
use lighthouse_metrics::*;

#[cfg(not(feature = "sysalloc"))]
use jemalloc_ctl::{arenas, epoch, stats};

lazy_static::lazy_static! {
    pub static ref PROCESS_NUM_THREADS: Result<IntGauge> = try_create_int_gauge(
        "process_num_threads",
        "Number of threads used by the current process"
    );
    pub static ref PROCESS_RES_MEM: Result<IntGauge> = try_create_int_gauge(
        "process_resident_memory_bytes",
        "Resident memory used by the current process"
    );
    pub static ref PROCESS_VIRT_MEM: Result<IntGauge> = try_create_int_gauge(
        "process_virtual_memory_bytes",
        "Virtual memory used by the current process"
    );
    pub static ref SYSTEM_VIRT_MEM_TOTAL: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_total_bytes", "Total system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_AVAILABLE: Result<IntGauge> = try_create_int_gauge(
        "system_virt_mem_available_bytes",
        "Available system virtual memory"
    );
    pub static ref SYSTEM_VIRT_MEM_USED: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_used_bytes", "Used system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_FREE: Result<IntGauge> =
        try_create_int_gauge("system_virt_mem_free_bytes", "Free system virtual memory");
    pub static ref SYSTEM_VIRT_MEM_PERCENTAGE: Result<Gauge> = try_create_float_gauge(
        "system_virt_mem_percentage",
        "Percentage of used virtual memory"
    );
    pub static ref SYSTEM_LOADAVG_1: Result<Gauge> =
        try_create_float_gauge("system_loadavg_1", "Loadavg over 1 minute");
    pub static ref SYSTEM_LOADAVG_5: Result<Gauge> =
        try_create_float_gauge("system_loadavg_5", "Loadavg over 5 minutes");
    pub static ref SYSTEM_LOADAVG_15: Result<Gauge> =
        try_create_float_gauge("system_loadavg_15", "Loadavg over 15 minutes");

    /*
     * jemalloc
     */
    pub static ref JEMALLOC_RESIDENT: Result<IntGauge> =
        try_create_int_gauge("jemalloc_resident", "Total number of bytes in physically resident data pages mapped by the allocator.");
    pub static ref JEMALLOC_ALLOCATED: Result<IntGauge> =
        try_create_int_gauge("jemalloc_allocated", "Total number of bytes allocated by the application.");
    pub static ref JEMALLOC_MAPPED: Result<IntGauge> =
        try_create_int_gauge("jemalloc_mapped", "Total number of bytes in active extents mapped by the allocator.");
    pub static ref JEMALLOC_METADATA: Result<IntGauge> =
        try_create_int_gauge("jemalloc_metadata", "Total number of bytes dedicated to jemalloc metadata.");
    pub static ref JEMALLOC_RETAINED: Result<IntGauge> =
        try_create_int_gauge("jemalloc_retained", "Total number of bytes in virtual memory mappings that were retained rather than being returned to the operating system.");
    pub static ref JEMALLOC_ACTIVE: Result<IntGauge> =
        try_create_int_gauge("jemalloc_active", "Total number of bytes in active pages allocated by the application.");
    pub static ref JEMALLOC_ARENAS: Result<IntGauge> =
        try_create_int_gauge("jemalloc_arenas", "Current limit on the number of arenas.");
}

pub fn scrape_health_metrics() {
    // This will silently fail if we are unable to observe the health. This is desired behaviour
    // since we don't support `Health` for all platforms.
    if let Ok(health) = Health::observe() {
        set_gauge(&PROCESS_NUM_THREADS, health.pid_num_threads as i64);
        set_gauge(&PROCESS_RES_MEM, health.pid_mem_resident_set_size as i64);
        set_gauge(&PROCESS_VIRT_MEM, health.pid_mem_virtual_memory_size as i64);
        set_gauge(&SYSTEM_VIRT_MEM_TOTAL, health.sys_virt_mem_total as i64);
        set_gauge(
            &SYSTEM_VIRT_MEM_AVAILABLE,
            health.sys_virt_mem_available as i64,
        );
        set_gauge(&SYSTEM_VIRT_MEM_USED, health.sys_virt_mem_used as i64);
        set_gauge(&SYSTEM_VIRT_MEM_FREE, health.sys_virt_mem_free as i64);
        set_float_gauge(
            &SYSTEM_VIRT_MEM_PERCENTAGE,
            health.sys_virt_mem_percent as f64,
        );
        set_float_gauge(&SYSTEM_LOADAVG_1, health.sys_loadavg_1);
        set_float_gauge(&SYSTEM_LOADAVG_5, health.sys_loadavg_5);
        set_float_gauge(&SYSTEM_LOADAVG_15, health.sys_loadavg_15);
    }

    scrape_jemalloc_metrics();
}

#[cfg(not(feature = "sysalloc"))]
pub fn scrape_jemalloc_metrics() {
    if epoch::advance().is_ok() {
        if let Ok(allocated) = stats::allocated::read() {
            set_gauge(&JEMALLOC_ALLOCATED, allocated as i64);
        }
        if let Ok(resident) = stats::resident::read() {
            set_gauge(&JEMALLOC_RESIDENT, resident as i64);
        }
        if let Ok(mapped) = stats::mapped::read() {
            set_gauge(&JEMALLOC_MAPPED, mapped as i64);
        }
        if let Ok(metadata) = stats::metadata::read() {
            set_gauge(&JEMALLOC_METADATA, metadata as i64);
        }
        if let Ok(retained) = stats::retained::read() {
            set_gauge(&JEMALLOC_RETAINED, retained as i64);
        }
        if let Ok(active) = stats::active::read() {
            set_gauge(&JEMALLOC_ACTIVE, active as i64);
        }
        if let Ok(narenas) = arenas::narenas::read() {
            set_gauge(&JEMALLOC_ARENAS, narenas as i64);
        }
    }
}

#[cfg(feature = "sysalloc")]
pub fn scrape_jemalloc_metrics() {
    // NO OP
}

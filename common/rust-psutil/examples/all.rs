use std::thread;
use std::time::Duration;

use psutil::*;

fn main() {
	let block_time = Duration::from_millis(1000);

	let mut cpu_percent_collector = cpu::CpuPercentCollector::new().unwrap();
	let mut cpu_times_percent_collector = cpu::CpuTimesPercentCollector::new().unwrap();

	let mut disk_io_counters_collector = disk::DiskIoCountersCollector::default();

	let mut net_io_counters_collector = network::NetIoCountersCollector::default();

	thread::sleep(block_time);

	let cpu_percents_percpu = cpu_percent_collector.cpu_percent_percpu().unwrap();
	let cpu_times_percpu = cpu::cpu_times_percpu().unwrap();
	let cpu_times_percent_percpu = cpu_times_percent_collector
		.cpu_times_percent_percpu()
		.unwrap();

	let disk_io_counters_per_partition = disk_io_counters_collector
		.disk_io_counters_per_partition()
		.unwrap();
	let partitions = disk::partitions_physical().unwrap();
	let disk_usage = disk::disk_usage("/").unwrap();

	let uptime = host::uptime().unwrap();
	let boot_time = host::boot_time().unwrap();
	let loadavg = host::loadavg().unwrap();

	let virtual_memory = memory::virtual_memory().unwrap();
	let swap_memory = memory::swap_memory().unwrap();

	let net_io_counters = net_io_counters_collector.net_io_counters().unwrap();

	let pids = process::pids().unwrap();
	let processes = process::processes().unwrap();

	let temperatures = sensors::temperatures();

	dbg!(cpu_percents_percpu);
	dbg!(cpu_times_percpu);
	dbg!(cpu_times_percent_percpu);

	dbg!(disk_io_counters_per_partition);
	dbg!(partitions);
	dbg!(disk_usage);

	dbg!(uptime);
	dbg!(boot_time);
	dbg!(loadavg);

	dbg!(virtual_memory);
	dbg!(swap_memory);

	dbg!(net_io_counters);

	dbg!(pids);
	dbg!(processes);

	dbg!(temperatures);
}

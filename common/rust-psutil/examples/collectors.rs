use std::thread;
use std::time::Duration;

use psutil::{cpu, disk, network};

fn main() {
	let block_time = Duration::from_millis(1000);

	let mut disk_io_counters_collector = disk::DiskIoCountersCollector::default();
	let mut prev_disk_io_counters = disk_io_counters_collector.disk_io_counters().unwrap();

	let mut net_io_counters_collector = network::NetIoCountersCollector::default();
	let mut prev_net_io_counters = net_io_counters_collector.net_io_counters().unwrap();

	let mut cpu_percent_collector = cpu::CpuPercentCollector::new().unwrap();

	loop {
		thread::sleep(block_time);

		let current_disk_io_counters = disk_io_counters_collector.disk_io_counters().unwrap();
		let current_net_io_counters = net_io_counters_collector.net_io_counters().unwrap();
		let cpu_percents = cpu_percent_collector.cpu_percent_percpu().unwrap();

		dbg!(current_disk_io_counters.clone() - prev_disk_io_counters);
		dbg!(current_net_io_counters.clone() - prev_net_io_counters);
		dbg!(cpu_percents);

		prev_disk_io_counters = current_disk_io_counters;
		prev_net_io_counters = current_net_io_counters;
	}
}

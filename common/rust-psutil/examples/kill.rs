//! Kill a process, reading it's PID as a cli argument.

use psutil::process::Process;

fn main() {
	let args: Vec<String> = std::env::args().collect();
	let process = Process::new(args[1].parse().unwrap()).unwrap();

	if let Err(error) = process.kill() {
		println!("Failed to kill process: {}.", error);
	};
}

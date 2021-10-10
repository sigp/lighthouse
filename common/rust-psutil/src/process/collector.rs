// #[cfg(feature = "serde")]
// use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use crate::process::{self, Process};
use crate::{Pid, Result};
// FIXME: Process cannot be serialized/deserialize, as a result,
//        neither this can be.
// #[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ProcessCollector {
	pub processes: BTreeMap<Pid, Process>,
}

/// Used to maintain a list of up-to-date processes while persisting cached data within the process
/// struct between each update. For example, processes cache CPU busy times in order to calculate
/// CPU percent.
impl ProcessCollector {
	pub fn new() -> Result<ProcessCollector> {
		let processes = process::processes()?
			.into_iter()
			.filter_map(|process| process.ok())
			.map(|process| (process.pid(), process))
			.collect();

		Ok(ProcessCollector { processes })
	}

	pub fn update(&mut self) -> Result<()> {
		let new = ProcessCollector::new()?.processes;

		// remove processes with a PID that is no longer in use
		let to_remove: Vec<Pid> = self
			.processes
			.iter()
			.filter(|(pid, _process)| !new.contains_key(pid))
			.map(|(pid, _process)| *pid)
			.collect();
		for id in to_remove {
			self.processes.remove(&id);
		}

		new.into_iter().for_each(|(pid, process)| {
			// add new processes and replace processes with reused PIDs
			if !self.processes.contains_key(&pid) || self.processes[&pid] != process {
				self.processes.insert(pid, process);
			} else {
				// Update data used for oneshot.
				#[cfg(target_os = "linux")]
				{
					self.processes.get_mut(&pid).unwrap().procfs_stat = process.procfs_stat;
				}
			}
		});

		Ok(())
	}
}

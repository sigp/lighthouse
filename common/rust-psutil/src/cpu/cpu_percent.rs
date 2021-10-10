use crate::cpu::CpuTimesPercentCollector;
use crate::{Percent, Result};

/// Get cpu percents in non-blocking mode.
///
/// Example:
///
/// ```
/// let mut cpu_percent_collector = psutil::cpu::CpuPercentCollector::new().unwrap();
///
/// let cpu_percent = cpu_percent_collector.cpu_percent().unwrap();
/// let cpu_percents_percpu = cpu_percent_collector.cpu_percent_percpu().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct CpuPercentCollector {
	cpu_times_percent_collector: CpuTimesPercentCollector,
}

impl CpuPercentCollector {
	/// Initialize the `CpuPercentCollector` so the method calls are ready to be used.
	pub fn new() -> Result<CpuPercentCollector> {
		let cpu_times_percent_collector = CpuTimesPercentCollector::new()?;

		Ok(CpuPercentCollector {
			cpu_times_percent_collector,
		})
	}

	/// Returns a cpu percent since the last time this was called or since
	/// `CpuPercentCollector::new()` was called.
	pub fn cpu_percent(&mut self) -> Result<Percent> {
		let percent = self.cpu_times_percent_collector.cpu_times_percent()?.busy();

		Ok(percent)
	}

	/// Returns a cpu percent for each cpu since the last time this was called or since
	/// `CpuPercentCollector::new()` was called.
	pub fn cpu_percent_percpu(&mut self) -> Result<Vec<Percent>> {
		let percents = self
			.cpu_times_percent_collector
			.cpu_times_percent_percpu()?
			.into_iter()
			.map(|cpu_times_percent| cpu_times_percent.busy())
			.collect();

		Ok(percents)
	}
}

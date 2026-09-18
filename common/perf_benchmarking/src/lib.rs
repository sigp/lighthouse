//! Benchmarking that measures and counts hardware performance (e.g., CPU instructions) instead of wall-clock time.
//!
//! Wall-clock timings can vary from run to run and depend on factors such as background processes, data like CPU instructions don't.
//! This type of hardware performance data provides a more reliable measurement of the benchmarking data.
//!
//! Counting uses the Linux `perf_event_open` interface, so it is only available on Linux and
//! requires access to hardware performance counters. On most distributions this means setting
//! `kernel.perf_event_paranoid` to `2` or lower:
//!
//! ```text
//! sudo sysctl kernel.perf_event_paranoid=2
//! ```

use criterion::Throughput;
use criterion::measurement::{Measurement, ValueFormatter};
#[cfg(target_os = "linux")]
use perf_event::{Builder, Counter, events::Hardware};
#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::io::Result;

/// A list of hardware performance data
/// To add another metric (e.g., CPU cycles), simply add a new variant here, then add an arm in `event` and `labels` methods
#[derive(Clone, Copy, Debug)]
pub enum Metric {
    //CPU instructions
    CpuInstructions,
}

impl Metric {
    #[cfg(target_os = "linux")]
    // For any new metric, add another arm in the match
    fn event(self) -> Hardware {
        match self {
            Metric::CpuInstructions => Hardware::INSTRUCTIONS,
        }
    }

    // Unit labels for reports
    // For any new metric, add another arm in the match
    fn labels(self) -> Labels {
        match self {
            Metric::CpuInstructions => Labels {
                plain: "instructions",
                kilo: "Kinstructions",
                mega: "Minstructions",
                giga: "Ginstructions",
                per_element: "instructions/elements",
                per_byte: "instructions/bytes",
            },
        }
    }
}

// The following methods are required to be implemented for the ValueFormatter trait
// https://docs.rs/criterion/0.8.2/criterion/measurement/trait.ValueFormatter.html
impl ValueFormatter for Metric {
    fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = self.labels().scale(typical_value);
        for value in values {
            *value *= factor;
        }
        unit
    }

    fn scale_throughputs(
        &self,
        _typical_value: f64,
        throughput: &Throughput,
        values: &mut [f64],
    ) -> &'static str {
        let labels = self.labels();
        match throughput {
            // If the benchmark test is using elements, we divide by the count to give throughput/elements (e.g., instructions/elements)
            Throughput::Elements(count) => {
                for value in values {
                    *value /= *count as f64;
                }
                labels.per_element
            }
            Throughput::Bytes(count) | Throughput::BytesDecimal(count) => {
                for value in values {
                    *value /= *count as f64;
                }
                labels.per_byte
            }
            _ => labels.plain,
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        self.labels().plain
    }
}

/// Criterion measurement reporting a hardware counter value per iteration.
pub struct HardwareCounter {
    #[cfg(target_os = "linux")]
    counter: RefCell<Counter>,
    metric: Metric,
}

impl HardwareCounter {
    /// Open the hardware counter for `metric` on the current process.
    #[cfg(target_os = "linux")]
    pub fn new(metric: Metric) -> Result<Self> {
        let counter = Builder::new().kind(metric.event()).build()?;
        Ok(Self {
            counter: RefCell::new(counter),
            metric,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(_metric: Metric) -> Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hardware performance counters are only supported on Linux",
        ))
    }
}

// This is the main thing connecting the perf-event to Criterion
// The following are required methods to implement the trait Measurement
// https://docs.rs/criterion/0.8.2/criterion/measurement/trait.Measurement.html
impl Measurement for HardwareCounter {
    // Method `start` hands this value to method `end`
    // the counter is reset in `start` and read in `end`, so the intermediate type is empty
    type Intermediate = ();
    // Hardware counters are whole numbers
    type Value = u64;

    #[cfg(target_os = "linux")]
    fn start(&self) -> Self::Intermediate {
        let mut counter = self.counter.borrow_mut();
        // Reset the counter, then start counting
        counter.reset().expect("failed to reset hardware counter");
        counter.enable().expect("failed to enable hardware counter");
    }

    #[cfg(target_os = "linux")]
    fn end(&self, _intermediate: Self::Intermediate) -> Self::Value {
        let mut counter = self.counter.borrow_mut();
        // Stop counting, then read the total
        counter
            .disable()
            .expect("failed to disable hardware counter");
        counter.read().expect("failed to read hardware counter")
    }

    // For operating systems that are not Linux
    #[cfg(not(target_os = "linux"))]
    fn start(&self) -> Self::Intermediate {
        panic!("hardware performance counters are only supported on Linux")
    }

    #[cfg(not(target_os = "linux"))]
    fn end(&self, _: Self::Intermediate) -> Self::Value {
        panic!("hardware performance counters are only supported on Linux")
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1.saturating_add(*v2)
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as f64
    }

    // The output of method formatter is type ValueFormatter
    fn formatter(&self) -> &dyn ValueFormatter {
        // Any type that implements ValueFormatter can be returned
        // The impl for Metric is below; it looks up the unit strings for this counter's metric
        &self.metric
    }
}

/// Unit labels for a metric
struct Labels {
    // unscaled unit, e.g., instructions
    plain: &'static str,
    // scaled unit, e.g., Kinstructions to mean it is 1000 instructions
    kilo: &'static str,
    mega: &'static str,
    giga: &'static str,
    per_element: &'static str,
    per_byte: &'static str,
}

impl Labels {
    fn scale(&self, typical_value: f64) -> (f64, &'static str) {
        if typical_value >= 1e9 {
            (1e-9, self.giga)
        } else if typical_value >= 1e6 {
            (1e-6, self.mega)
        } else if typical_value >= 1e3 {
            (1e-3, self.kilo)
        } else {
            (1.0, self.plain)
        }
    }
}

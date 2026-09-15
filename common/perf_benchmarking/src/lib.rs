//! A [`criterion`] measurement that counts hardware performance data (e.g., CPU instructions) instead of wall-clock time.
//!
//! Wall-clock timings vary from run to run and depend on factors such as background processes, data like CPU instructions don't.
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

/// Criterion measurement reporting retired user-space CPU instructions per iteration.
pub struct InstructionCount {
    #[cfg(target_os = "linux")]
    counter: RefCell<Counter>,
}

impl InstructionCount {
    /// Open the hardware instruction counter for the current process.
    #[cfg(target_os = "linux")]
    pub fn new() -> Result<Self> {
        let mut builder = Builder::new().kind(Hardware::INSTRUCTIONS);
        builder.exclude_kernel(true).exclude_hv(true);
        let counter = builder.build()?;
        Ok(Self {
            counter: RefCell::new(counter),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hardware instruction counters are only supported on Linux",
        ))
    }
}

// The following are required methods to implement the trait Measurement
// https://docs.rs/criterion/0.8.2/criterion/measurement/trait.Measurement.html
impl Measurement for InstructionCount {
    // Method `start` hands this value to method `end`
    // the counter is reset in `start` and read in `end`, so the intermediate type is empty
    type Intermediate = ();
    // CPU instructions are in the form of integers
    type Value = u64;

    #[cfg(target_os = "linux")]
    fn start(&self) -> Self::Intermediate {
        let mut counter = self.counter.borrow_mut();
        // Zero the counter, then start counting
        counter
            .reset()
            .expect("failed to reset instruction counter");
        counter
            .enable()
            .expect("failed to enable instruction counter");
    }

    #[cfg(target_os = "linux")]
    fn end(&self, _intermediate: Self::Intermediate) -> Self::Value {
        let mut counter = self.counter.borrow_mut();
        // Stop counting, then read the total
        counter
            .disable()
            .expect("failed to disable instruction counter");
        counter.read().expect("failed to read instruction counter")
    }

    // For operating systems that are not Linux
    #[cfg(not(target_os = "linux"))]
    fn start(&self) -> Self::Intermediate {
        unreachable!("InstructionCount cannot be constructed on this platform")
    }

    #[cfg(not(target_os = "linux"))]
    fn end(&self, _: Self::Intermediate) -> Self::Value {
        unreachable!("InstructionCount cannot be constructed on this platform")
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
        // The impl of InstructionFormatter is below
        &InstructionFormatter
    }
}

struct InstructionFormatter;

impl InstructionFormatter {
    fn scale(count: f64) -> (f64, &'static str) {
        if count >= 1e9 {
            (1e-9, "Ginstructions")
        } else if count >= 1e6 {
            (1e-6, "Minstructions")
        } else if count >= 1e3 {
            (1e-3, "Kinstructions")
        } else {
            (1.0, "instructions")
        }
    }
}

// The following methods are required to be implemented for the ValueFormatter trait
// https://docs.rs/criterion/0.8.2/criterion/measurement/trait.ValueFormatter.html
impl ValueFormatter for InstructionFormatter {
    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "instructions"
    }

    fn scale_throughputs(
        &self,
        _typical: f64,
        throughput: &Throughput,
        values: &mut [f64],
    ) -> &'static str {
        match throughput {
            Throughput::Elements(count) => {
                for value in values {
                    *value /= *count as f64;
                }
                "instructions/elements"
            }
            Throughput::Bytes(count) | Throughput::BytesDecimal(count) => {
                for value in values {
                    *value /= *count as f64;
                }
                "instructions/bytes"
            }
            _ => "instructions",
        }
    }

    fn scale_values(&self, typical: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = Self::scale(typical);
        for value in values {
            *value *= factor;
        }
        unit
    }
}

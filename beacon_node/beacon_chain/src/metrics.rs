pub use prometheus::Error;
use prometheus::{Histogram, HistogramOpts, IntCounter, Opts, Registry};

pub struct Metrics {
    pub block_processing_requests: IntCounter,
    pub block_processing_successes: IntCounter,
    pub block_processing_historgram: Histogram,
    pub block_production_requests: IntCounter,
    pub block_production_successes: IntCounter,
    pub block_production_historgram: Histogram,
    pub attestation_production_requests: IntCounter,
    pub attestation_production_successes: IntCounter,
    pub attestation_production_histogram: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            block_processing_requests: {
                let opts = Opts::new("blocks_processed", "total_blocks_processed");
                IntCounter::with_opts(opts)?
            },
            block_processing_successes: {
                let opts = Opts::new("valid_blocks_processed", "total_valid_blocks_processed");
                IntCounter::with_opts(opts)?
            },
            block_processing_historgram: {
                let opts =
                    HistogramOpts::new("block_processing_historgram", "block_processing_time");
                Histogram::with_opts(opts)?
            },
            block_production_requests: {
                let opts = Opts::new("block_production_requests", "attempts_to_produce_new_block");
                IntCounter::with_opts(opts)?
            },
            block_production_successes: {
                let opts = Opts::new("block_production_successes", "blocks_successfully_produced");
                IntCounter::with_opts(opts)?
            },
            block_production_historgram: {
                let opts =
                    HistogramOpts::new("block_production_historgram", "block_production_time");
                Histogram::with_opts(opts)?
            },
            attestation_production_requests: {
                let opts = Opts::new(
                    "attestation_production_requests",
                    "total_attestation_production_requests",
                );
                IntCounter::with_opts(opts)?
            },
            attestation_production_successes: {
                let opts = Opts::new(
                    "attestation_production_successes",
                    "total_attestation_production_successes",
                );
                IntCounter::with_opts(opts)?
            },
            attestation_production_histogram: {
                let opts = HistogramOpts::new(
                    "attestation_production_histogram",
                    "attestation_production_time",
                );
                Histogram::with_opts(opts)?
            },
        })
    }

    pub fn register(&self, registry: &Registry) -> Result<(), Error> {
        registry.register(Box::new(self.block_processing_requests.clone()))?;
        registry.register(Box::new(self.block_processing_successes.clone()))?;
        registry.register(Box::new(self.block_processing_historgram.clone()))?;
        registry.register(Box::new(self.block_production_requests.clone()))?;
        registry.register(Box::new(self.block_production_successes.clone()))?;
        registry.register(Box::new(self.block_production_historgram.clone()))?;
        registry.register(Box::new(self.attestation_production_requests.clone()))?;
        registry.register(Box::new(self.attestation_production_successes.clone()))?;
        registry.register(Box::new(self.attestation_production_histogram.clone()))?;

        Ok(())
    }
}

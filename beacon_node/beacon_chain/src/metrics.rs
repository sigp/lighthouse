pub use prometheus::Error;
use prometheus::{Histogram, HistogramOpts, IntCounter, Opts, Registry};

pub struct Metrics {
    pub block_processing_requests: IntCounter,
    pub block_processing_successes: IntCounter,
    pub block_processing_times: Histogram,
    pub block_production_requests: IntCounter,
    pub block_production_successes: IntCounter,
    pub block_production_times: Histogram,
    pub attestation_production_requests: IntCounter,
    pub attestation_production_successes: IntCounter,
    pub attestation_production_times: Histogram,
    pub attestation_processing_requests: IntCounter,
    pub attestation_processing_successes: IntCounter,
    pub attestation_processing_times: Histogram,
    pub fork_choice_requests: IntCounter,
    pub fork_choice_changed_head: IntCounter,
    pub fork_choice_reorg_count: IntCounter,
    pub fork_choice_times: Histogram,
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
            block_processing_times: {
                let opts = HistogramOpts::new("block_processing_times", "block_processing_time");
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
            block_production_times: {
                let opts = HistogramOpts::new("block_production_times", "block_production_time");
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
            attestation_production_times: {
                let opts = HistogramOpts::new(
                    "attestation_production_times",
                    "attestation_production_time",
                );
                Histogram::with_opts(opts)?
            },
            attestation_processing_requests: {
                let opts = Opts::new(
                    "attestation_processing_requests",
                    "total_attestation_processing_requests",
                );
                IntCounter::with_opts(opts)?
            },
            attestation_processing_successes: {
                let opts = Opts::new(
                    "attestation_processing_successes",
                    "total_attestation_processing_successes",
                );
                IntCounter::with_opts(opts)?
            },
            attestation_processing_times: {
                let opts = HistogramOpts::new(
                    "attestation_processing_times",
                    "attestation_processing_time",
                );
                Histogram::with_opts(opts)?
            },
            fork_choice_requests: {
                let opts = Opts::new("fork_choice_requests", "total_times_fork_choice_called");
                IntCounter::with_opts(opts)?
            },
            fork_choice_changed_head: {
                let opts = Opts::new(
                    "fork_choice_changed_head",
                    "total_times_fork_choice_chose_a_new_head",
                );
                IntCounter::with_opts(opts)?
            },
            fork_choice_reorg_count: {
                let opts = Opts::new("fork_choice_reorg_depth", "depth_of_reorg");
                IntCounter::with_opts(opts)?
            },
            fork_choice_times: {
                let opts = HistogramOpts::new("fork_choice_time", "total_time_to_run_fork_choice");
                Histogram::with_opts(opts)?
            },
        })
    }

    pub fn register(&self, registry: &Registry) -> Result<(), Error> {
        registry.register(Box::new(self.block_processing_requests.clone()))?;
        registry.register(Box::new(self.block_processing_successes.clone()))?;
        registry.register(Box::new(self.block_processing_times.clone()))?;
        registry.register(Box::new(self.block_production_requests.clone()))?;
        registry.register(Box::new(self.block_production_successes.clone()))?;
        registry.register(Box::new(self.block_production_times.clone()))?;
        registry.register(Box::new(self.attestation_production_requests.clone()))?;
        registry.register(Box::new(self.attestation_production_successes.clone()))?;
        registry.register(Box::new(self.attestation_production_times.clone()))?;
        registry.register(Box::new(self.attestation_processing_requests.clone()))?;
        registry.register(Box::new(self.attestation_processing_successes.clone()))?;
        registry.register(Box::new(self.attestation_processing_times.clone()))?;
        registry.register(Box::new(self.fork_choice_requests.clone()))?;
        registry.register(Box::new(self.fork_choice_changed_head.clone()))?;
        registry.register(Box::new(self.fork_choice_reorg_count.clone()))?;
        registry.register(Box::new(self.fork_choice_times.clone()))?;

        Ok(())
    }
}

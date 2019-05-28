pub use prometheus::Error;
use prometheus::{IntCounter, Opts, Registry};

pub struct Metrics {
    pub blocks_processed: IntCounter,
    pub valid_blocks_processed: IntCounter,
    pub block_production_requests: IntCounter,
    pub block_production_successes: IntCounter,
    pub attestation_production_requests: IntCounter,
    pub attestation_production_successes: IntCounter,
}

impl Metrics {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            blocks_processed: {
                let opts = Opts::new("blocks_processed", "total_blocks_processed");
                IntCounter::with_opts(opts)?
            },
            valid_blocks_processed: {
                let opts = Opts::new("valid_blocks_processed", "total_valid_blocks_processed");
                IntCounter::with_opts(opts)?
            },
            block_production_requests: {
                let opts = Opts::new("block_production_requests", "attempts_to_produce_new_block");
                IntCounter::with_opts(opts)?
            },
            block_production_successes: {
                let opts = Opts::new("block_production_successes", "blocks_successfully_produced");
                IntCounter::with_opts(opts)?
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
        })
    }

    pub fn register(&self, registry: &Registry) -> Result<(), Error> {
        registry.register(Box::new(self.blocks_processed.clone()))?;
        registry.register(Box::new(self.valid_blocks_processed.clone()))?;
        registry.register(Box::new(self.block_production_requests.clone()))?;
        registry.register(Box::new(self.block_production_successes.clone()))?;
        registry.register(Box::new(self.attestation_production_requests.clone()))?;
        registry.register(Box::new(self.attestation_production_successes.clone()))?;

        Ok(())
    }
}

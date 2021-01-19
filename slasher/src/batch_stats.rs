#[derive(Debug)]
pub struct BatchStats {
    pub block_stats: BlockStats,
    pub attestation_stats: AttestationStats,
}

#[derive(Debug)]
pub struct BlockStats {
    pub num_processed: usize,
    pub num_slashings: usize,
}

#[derive(Debug)]
pub struct AttestationStats {
    pub num_processed: usize,
}

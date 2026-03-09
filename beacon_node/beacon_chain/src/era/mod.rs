/// ERA file support for importing and exporting historical beacon chain data.
///
/// ERA files store beacon blocks and states in a standardized archive format, enabling
/// efficient distribution of historical chain data between clients. Each ERA file covers
/// one "era" of `SLOTS_PER_HISTORICAL_ROOT` slots (8192 on mainnet) and contains:
/// - All beacon blocks in the slot range
/// - The boundary `BeaconState` at the end of the range
///
/// Verification relies on `historical_roots` (pre-Capella) and `historical_summaries`
/// (post-Capella) which commit to the block and state roots for each era.
///
/// Spec: <https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#historical-roots-updates>
/// Format: <https://github.com/status-im/nimbus-eth2/blob/stable/docs/the_auditors_handbook/src/02.4_the_era_file_format.md>
pub mod consumer;
pub mod producer;
pub mod store_init;

#[cfg(test)]
mod tests;

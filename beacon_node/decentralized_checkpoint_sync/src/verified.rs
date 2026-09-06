use crate::beacon_header;
use types::{EthSpec, ForkName, Hash256, LightClientHeader, Slot};

/// A checkpoint header anchored in an externally trusted finalized root or verified finality.
///
/// Bootstrap initialization inherits the caller's trust in the supplied finalized block root;
/// the bootstrap does not independently prove finality. Later light-client processing may only
/// advance this header through verified supermajority finality, never through a force update.
/// There is deliberately no public constructor or deserialization implementation.
///
/// Transport code cannot promote a decoded header directly:
///
/// ```compile_fail,E0624
/// use decentralized_checkpoint_sync::VerifiedFinalizedHeader;
/// use types::{ForkName, LightClientHeader, LightClientHeaderAltair, MinimalEthSpec};
///
/// let header = LightClientHeader::Altair(LightClientHeaderAltair::<MinimalEthSpec>::default());
/// let trusted = VerifiedFinalizedHeader::from_trusted_bootstrap(header, ForkName::Altair);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedFinalizedHeader<E: EthSpec> {
    header: LightClientHeader<E>,
    beacon_block_root: Hash256,
    fork: ForkName,
}

impl<E: EthSpec> VerifiedFinalizedHeader<E> {
    /// The caller must have validated the header, its trusted root and the bootstrap committee.
    pub(crate) fn from_trusted_bootstrap(header: LightClientHeader<E>, fork: ForkName) -> Self {
        Self {
            beacon_block_root: beacon_header(&header).canonical_root(),
            header,
            fork,
        }
    }

    pub fn header(&self) -> &LightClientHeader<E> {
        &self.header
    }

    pub fn beacon_block_root(&self) -> Hash256 {
        self.beacon_block_root
    }

    pub fn beacon_state_root(&self) -> Hash256 {
        beacon_header(&self.header).state_root
    }

    pub fn slot(&self) -> Slot {
        beacon_header(&self.header).slot
    }

    /// The fork at the beacon slot, which may differ from the header's upgraded wire schema.
    pub fn fork(&self) -> ForkName {
        self.fork
    }
}

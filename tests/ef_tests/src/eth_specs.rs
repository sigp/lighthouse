use types::{EthSpec, typenum::{U64, U8}, ChainSpec, FewValidatorsEthSpec};
use serde_derive::{Serialize, Deserialize};

/// "Minimal" testing specification, as defined here:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/configs/constant_presets/minimal.yaml
///
/// Spec v0.6.1
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct MinimalEthSpec;

impl EthSpec for MinimalEthSpec {
    type ShardCount = U8;
    type SlotsPerHistoricalRoot = U64;
    type LatestRandaoMixesLength = U64;
    type LatestActiveIndexRootsLength = U64;
    type LatestSlashedExitLength = U64;

    fn spec() -> ChainSpec {
        // TODO: this spec is likely incorrect!
        FewValidatorsEthSpec::spec()
    }
}

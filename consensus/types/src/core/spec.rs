//! Compile-time `Spec` selection.
//!
//! `EthSpec` still defines the preset consts but they will move here eventually.

#[cfg(all(feature = "spec-gnosis", not(feature = "spec-minimal")))]
use crate::GnosisEthSpec;
#[cfg(not(any(feature = "spec-minimal", feature = "spec-gnosis")))]
use crate::MainnetEthSpec;
#[cfg(feature = "spec-minimal")]
use crate::MinimalEthSpec;

#[cfg(all(feature = "spec-minimal", feature = "spec-gnosis"))]
compile_error!(
    "`spec-minimal` and `spec-gnosis` select different presets and are mutually exclusive. \
     Enable at most one."
);

/// The spec selected at compile time.
///
/// This allows tests to compile under a single preset.
#[cfg(not(any(feature = "spec-minimal", feature = "spec-gnosis")))]
pub type Spec = MainnetEthSpec;

#[cfg(feature = "spec-minimal")]
pub type Spec = MinimalEthSpec;

#[cfg(all(feature = "spec-gnosis", not(feature = "spec-minimal")))]
pub type Spec = GnosisEthSpec;

#[cfg(test)]
mod test {
    use super::Spec;
    use crate::{EthSpec, EthSpecId};

    /// `Spec` must follow the preset feature this build was compiled with.
    #[test]
    fn spec_follows_feature() {
        let expected = if cfg!(feature = "spec-minimal") {
            EthSpecId::Minimal
        } else if cfg!(feature = "spec-gnosis") {
            EthSpecId::Gnosis
        } else {
            EthSpecId::Mainnet
        };
        assert_eq!(Spec::spec_name(), expected);
    }
}

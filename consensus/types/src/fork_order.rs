use crate::{FeatureName, ForkName};
use superstruct::superstruct;

#[superstruct(variants_and_features_decl = "FORK_ORDER")]
pub const FORK_ORDER: &[(ForkName, &[FeatureName])] = &[
    (ForkName::Base, &[]),
    (ForkName::Altair, &[FeatureName::Altair]),
    (ForkName::Merge, &[FeatureName::Merge]),
    (ForkName::Capella, &[FeatureName::Capella]),
    (ForkName::Deneb, &[FeatureName::Deneb]),
    (ForkName::Electra, &[FeatureName::Electra]),
];

#[superstruct(feature_dependencies_decl = "FEATURE_DEPENDENCIES")]
pub const FEATURE_DEPENDENCIES: &[(FeatureName, &[FeatureName])] = &[
    (FeatureName::Altair, &[]),
    (FeatureName::Merge, &[FeatureName::Altair]),
    (FeatureName::Capella, &[FeatureName::Merge]),
    (FeatureName::Deneb, &[FeatureName::Capella]),
    (FeatureName::Electra, &[FeatureName::Deneb]),
];

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn partial_ord_sanity_check() {
        for (fork_a, fork_b) in FORK_ORDER.iter().map(|(fork, _)| fork).tuple_windows() {
            assert!(fork_a < fork_b, "{fork_a} < {fork_b}");
            assert_eq!(fork_a, fork_a);
            assert_eq!(fork_b, fork_b);
        }
    }
}

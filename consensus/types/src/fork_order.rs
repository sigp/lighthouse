use crate::{FeatureName, ForkName};
use superstruct::superstruct;

#[superstruct(variants_and_features_decl = "FORK_ORDER")]
pub const FORK_ORDER: &[(ForkName, &[FeatureName])] = &[
    (ForkName::Base, &[]),
    (ForkName::Altair, &[FeatureName::SyncCommittees]),
    (ForkName::Merge, &[FeatureName::Merge]),
    (ForkName::Capella, &[FeatureName::Withdrawals]),
    (ForkName::Deneb, &[FeatureName::Blobs]),
    (ForkName::Electra, &[]),
];

#[superstruct(feature_dependencies_decl = "FEATURE_DEPENDENCIES")]
pub const FEATURE_DEPENDENCIES: &[(FeatureName, &[FeatureName])] = &[
    (FeatureName::SyncCommittees, &[]),
    (FeatureName::Merge, &[FeatureName::SyncCommittees]),
    (FeatureName::Withdrawals, &[FeatureName::Merge]),
    (FeatureName::Blobs, &[FeatureName::Withdrawals]),
];

//! Types for the Gloas builder flow that are defined by the Builder API and beacon-APIs specs
//! (builder-specs, beacon-APIs) rather than the consensus-specs.
//!
//! These are wire/request types — they never participate in the state transition — so they live
//! above `consensus/types` rather than in it. Consensus-spec builder containers (`Builder`,
//! `BuilderPendingPayment`, `SignedExecutionPayloadBid`, `ProposerPreferences`, ...) remain in
//! `types`.

/// Local equivalent of the `ssz_and_tree_hash_tests!` macro in `consensus/types`, which cannot be
/// reused here because it is `#![cfg(test)]`-gated to that crate. Builds an arbitrary instance via
/// `types::test_utils::test_arbitrary_instance` (available with the `arbitrary` feature) and checks
/// SSZ round-trips and tree hashing does not panic.
#[cfg(test)]
#[macro_use]
mod test_macros {
    macro_rules! ssz_and_tree_hash_tests {
        ($type:ty) => {
            #[test]
            fn ssz_round_trip() {
                let original: $type = types::test_utils::test_arbitrary_instance();
                let bytes = ssz::ssz_encode(&original);
                let decoded = <$type as ssz::Decode>::from_ssz_bytes(&bytes).unwrap();
                assert_eq!(original, decoded);
            }

            #[test]
            fn tree_hash_root_does_not_panic() {
                let original: $type = types::test_utils::test_arbitrary_instance();
                let _ = tree_hash::TreeHash::tree_hash_root(&original);
            }
        };
    }
}

mod builder_config;
mod builder_entry;
mod builder_preference_entry;
mod builder_preferences;
mod builder_preferences_request;
mod builder_url;
mod request_auth;
mod signed_request_auth;

pub use builder_config::BuilderConfig;
pub use builder_entry::{BuilderEntry, BuilderPubkeys, MaxBuilderPubkeys};
pub use builder_preference_entry::{
    BuilderPreferenceEntry, MAX_SUBMITTED_BUILDER_PREFERENCES, MaxSubmittedBuilderPreferences,
    SubmittedBuilderPreferences,
};
pub use builder_preferences::BuilderPreferences;
pub use builder_preferences_request::BuilderPreferencesRequest;
pub use builder_url::{
    BuilderUrl, BuilderUrlError, MAX_BUILDER_ENTRIES, MaxBuilderEntries, MaxBuilderUrlSize,
};
pub use request_auth::{MaxDataSize, RequestAuth, RequestAuthData};
pub use signed_request_auth::SignedRequestAuth;

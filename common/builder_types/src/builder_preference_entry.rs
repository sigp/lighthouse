use crate::{BuilderEntry, BuilderUrl, SignedRequestAuth};
use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum;
use tree_hash_derive::TreeHash;

/// `MAX_BUILDER_ENTRIES * (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH` (with mainnet
/// `SLOTS_PER_EPOCH`), the bound on the entry list of a single `submitBuilderPreferences`
/// beacon-API submission, per beacon-APIs #630. A fixed wire constant, not preset-derived.
pub type MaxSubmittedBuilderPreferences = typenum::U4096;

/// [`MaxSubmittedBuilderPreferences`] as a `usize` (derived, so the two cannot drift), for runtime
/// bounds checks.
pub const MAX_SUBMITTED_BUILDER_PREFERENCES: usize =
    <MaxSubmittedBuilderPreferences as typenum::Unsigned>::USIZE;

/// The bounded entry list of a single `submitBuilderPreferences` beacon-API submission
/// (SSZ `List[BuilderPreferencesEntry, 4096]`, per beacon-APIs #630).
pub type SubmittedBuilderPreferences =
    ssz_types::VariableList<BuilderPreferenceEntry, MaxSubmittedBuilderPreferences>;

/// A per-builder preference a validator asks the beacon node to submit ahead of the bid request,
/// one entry per `submitBuilderPreferences` builder-API call the beacon node will make.
///
/// This is the beacon-API (validator -> beacon node) type from beacon-APIs #630. Each entry names
/// its `proposer_pubkey`, so one flat request can carry preferences for several proposers. Unlike
/// the block-production `BuilderEntry`, it carries only what a builder is allowed to see: the routing
/// `url`, the forwarded `auth`, and the `max_execution_payment` cap. The proposer's private
/// bid-filtering knobs (`min_bid`, `builder_boost_factor`) are never sent to a builder.
///
/// SSZ container (field order per the spec — SSZ and tree-hash depend on it):
/// ```text
/// class BuilderPreferenceEntry(Container):
///     proposer_pubkey: BLSPubkey
///     url: ByteList[MAX_BUILDER_URL_SIZE]
///     auth: SignedRequestAuth
///     max_execution_payment: Gwei
/// ```
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BuilderPreferenceEntry {
    /// The proposer these preferences belong to.
    pub proposer_pubkey: PublicKeyBytes,
    /// The URL the beacon node submits these preferences to. Unsigned routing metadata.
    pub url: BuilderUrl,
    /// Authenticates the submission to the builder; forwarded byte-for-byte unchanged.
    pub auth: SignedRequestAuth,
    /// Maximum trusted execution-layer payment (Gwei) the proposer will accept from this builder.
    #[serde(with = "serde_utils::quoted_u64")]
    pub max_execution_payment: u64,
}

impl BuilderPreferenceEntry {
    /// Enforce the wire-validity rules from beacon-APIs #630: in either encoding, a zero-length
    /// `url` and a zero-length `auth.message.data` are invalid, making the containing body an
    /// invalid request (400).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.url.as_bytes().is_empty() {
            return Err("zero-length builder url");
        }
        if self.auth.message.data.is_empty() {
            return Err("zero-length auth data");
        }
        Ok(())
    }

    pub fn new(
        proposer_pubkey: PublicKeyBytes,
        url: BuilderUrl,
        auth: SignedRequestAuth,
        max_execution_payment: u64,
    ) -> Self {
        Self {
            proposer_pubkey,
            url,
            auth,
            max_execution_payment,
        }
    }

    /// Narrow a proposer's block-production [`BuilderEntry`] to the beacon-API preference entry,
    /// dropping the builder-only fields (`min_bid`, `builder_boost_factor`, `builder_pubkeys`).
    pub fn from_builder_entry(proposer_pubkey: PublicKeyBytes, entry: BuilderEntry) -> Self {
        Self {
            proposer_pubkey,
            url: entry.url,
            auth: entry.auth,
            max_execution_payment: entry.max_execution_payment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderPreferenceEntry);
}

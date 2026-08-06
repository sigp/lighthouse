use crate::{BuilderUrl, SignedRequestAuth};
use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// A per-builder bid request the validator client supplies on a block-production request, per
/// [beacon-APIs #630](https://github.com/ethereum/beacon-APIs/pull/630).
///
/// Each entry is a direct bid request: the beacon node calls `getExecutionPayloadBid` at `url`,
/// authenticated by `auth`. One request is made per entry, so several entries MAY share a `url`
/// with different `auth`. `min_bid`/`builder_boost_factor`/`max_execution_payment` are this
/// builder's per-request selection policy; p2p bids are governed by the global values on the
/// enclosing config, not here.
///
/// `builder_pubkey` is optional (its all-zero value means unset — resolve it via the
/// [`builder_pubkey`](Self::builder_pubkey) accessor). When set, it filters the response: a bid not
/// signed by it MUST NOT be accepted. SSZ cannot express absence, hence the sentinel.
///
/// Field order matches the SSZ `BuilderEntry` container:
/// ```text
/// class BuilderEntry(Container):
///     url: ByteList[MAX_BUILDER_URL_SIZE]
///     auth: SignedRequestAuth
///     builder_pubkey: BLSPubkey
///     max_execution_payment: Gwei
///     min_bid: Gwei
///     builder_boost_factor: uint64
/// ```
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BuilderEntry {
    /// Where this entry's bid request is sent. Required and non-empty: beacon-APIs #630 treats a
    /// zero-length url as invalid. p2p bid policy is carried by the top-level `BuilderConfig`.
    pub url: BuilderUrl,
    /// Authenticates this entry's bid request.
    pub auth: SignedRequestAuth,
    /// If set, the returned bid must be signed by this key or it MUST NOT be accepted. Unset is
    /// all-zero.
    #[serde(
        default = "PublicKeyBytes::empty",
        skip_serializing_if = "pubkey_is_unset"
    )]
    pub builder_pubkey: PublicKeyBytes,
    /// Maximum trusted execution-layer payment (Gwei) accepted from this builder.
    #[serde(with = "serde_utils::quoted_u64")]
    pub max_execution_payment: u64,
    /// Minimum total payment (Gwei) for a bid from this builder to be accepted.
    #[serde(with = "serde_utils::quoted_u64")]
    pub min_bid: u64,
    /// Percentage multiplier applied to this builder's bid when comparing against the local payload.
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_boost_factor: u64,
}

impl BuilderEntry {
    /// The builder pubkey the bid response must be signed by, or `None` when unset.
    pub fn builder_pubkey(&self) -> Option<PublicKeyBytes> {
        (!pubkey_is_unset(&self.builder_pubkey)).then_some(self.builder_pubkey)
    }
}

/// Whether a `builder_pubkey` is unset (all-zero). A free function, used for the field's
/// `skip_serializing_if`, because `PublicKeyBytes` is a foreign type without an `is_empty` method
/// (unlike `BuilderUrl`/`SignedRequestAuth`, which carry their own predicates).
fn pubkey_is_unset(pubkey: &PublicKeyBytes) -> bool {
    *pubkey == PublicKeyBytes::empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderEntry);

    fn entry() -> BuilderEntry {
        BuilderEntry {
            url: "http://builder.example.com".parse().unwrap(),
            auth: SignedRequestAuth::unset(),
            builder_pubkey: PublicKeyBytes::empty(),
            max_execution_payment: 1,
            min_bid: 2,
            builder_boost_factor: 100,
        }
    }

    #[test]
    fn json_omits_unset_builder_pubkey() {
        // `url` and `auth` are always present; only an unset `builder_pubkey` is omitted.
        let entry = entry();
        let json = serde_json::to_value(&entry).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("url"));
        assert!(obj.contains_key("auth"));
        assert!(!obj.contains_key("builder_pubkey"));

        // The omitted `builder_pubkey` deserializes back to its unset sentinel.
        assert_eq!(serde_json::from_value::<BuilderEntry>(json).unwrap(), entry);
    }

    #[test]
    fn json_includes_set_builder_pubkey() {
        let mut entry = entry();
        entry.builder_pubkey = PublicKeyBytes::deserialize(&[1u8; 48]).unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.as_object().unwrap().contains_key("builder_pubkey"));

        assert_eq!(serde_json::from_value::<BuilderEntry>(json).unwrap(), entry);
    }
}

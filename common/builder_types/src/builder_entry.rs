use crate::{BuilderUrl, SignedRequestAuth};
use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{VariableList, typenum};
use tree_hash_derive::TreeHash;

/// `MAX_BUILDER_PUBKEYS` (beacon-APIs #630) as a typenum, bounding a [`BuilderEntry`]'s
/// `builder_pubkeys` list.
pub type MaxBuilderPubkeys = typenum::U64;

/// The builder pubkeys a [`BuilderEntry`] accepts bids from. Empty accepts any builder.
pub type BuilderPubkeys = VariableList<PublicKeyBytes, MaxBuilderPubkeys>;

/// A per-builder bid request the validator client supplies on a block-production request, per
/// [beacon-APIs #630](https://github.com/ethereum/beacon-APIs/pull/630).
///
/// Each entry is a direct bid request: the beacon node calls `getExecutionPayloadBid` at `url`,
/// authenticated by `auth`. One request is made per entry, so several entries MAY share a `url`
/// with different `auth`. `min_bid`/`builder_boost_factor`/`max_execution_payment` are this
/// builder's per-request selection policy; p2p bids are governed by the global values on the
/// enclosing config, not here.
///
/// `builder_pubkeys` filters the response: an empty list accepts any builder, and a bid not signed
/// by one of a non-empty list MUST NOT be accepted.
///
/// Field order matches the SSZ `BuilderEntry` container:
/// ```text
/// class BuilderEntry(Container):
///     url: ByteList[MAX_BUILDER_URL_SIZE]
///     auth: SignedRequestAuth
///     builder_pubkeys: List[BLSPubkey, MAX_BUILDER_PUBKEYS]
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
    /// The builder pubkeys this entry accepts bids from. Empty accepts any builder; otherwise a
    /// bid not signed by one of them MUST NOT be accepted.
    pub builder_pubkeys: BuilderPubkeys,
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
    /// Enforce the wire-validity rules from beacon-APIs #630: in either encoding, a zero-length
    /// `url` and a zero-length `auth.message.data` are invalid. A body containing such an entry is
    /// an invalid request (400), unlike per-entry failures (unreachable builder, rejected bid),
    /// which are isolated and never fail the request.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.url.as_bytes().is_empty() {
            return Err("zero-length builder url");
        }
        if self.auth.message.data.is_empty() {
            return Err("zero-length auth data");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BuilderEntry);

    fn test_auth() -> SignedRequestAuth {
        SignedRequestAuth {
            message: crate::RequestAuth {
                data: crate::RequestAuthData::new(b"http://builder.example.com".to_vec()).unwrap(),
                slot: types::Slot::new(0),
            },
            signature: bls::Signature::empty(),
        }
    }

    fn entry() -> BuilderEntry {
        BuilderEntry {
            url: "http://builder.example.com".parse().unwrap(),
            auth: test_auth(),
            builder_pubkeys: BuilderPubkeys::default(),
            max_execution_payment: 1,
            min_bid: 2,
            builder_boost_factor: 100,
        }
    }

    #[test]
    fn json_requires_builder_pubkeys() {
        // `builder_pubkeys` is a required field (beacon-APIs #630): an empty list is serialized as
        // `[]`, never omitted, and a body missing the field is rejected.
        let entry = entry();
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json.get("builder_pubkeys"), Some(&serde_json::json!([])));

        let mut without_field = json.clone();
        without_field
            .as_object_mut()
            .unwrap()
            .remove("builder_pubkeys");
        assert!(serde_json::from_value::<BuilderEntry>(without_field).is_err());

        assert_eq!(serde_json::from_value::<BuilderEntry>(json).unwrap(), entry);
    }

    #[test]
    fn json_round_trips_builder_pubkeys() {
        let mut entry = entry();
        entry.builder_pubkeys =
            BuilderPubkeys::new(vec![PublicKeyBytes::deserialize(&[1u8; 48]).unwrap()]).unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["builder_pubkeys"].as_array().unwrap().len(), 1);

        assert_eq!(serde_json::from_value::<BuilderEntry>(json).unwrap(), entry);
    }
}

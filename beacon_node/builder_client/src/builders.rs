use crate::{BuilderHttpClient, Error as BuilderClientError};
use bls::PublicKeyBytes;
use eth2::types::{
    BuilderEntry, BuilderPreferenceEntry, BuilderPreferences, BuilderPreferencesRequest,
    BuilderPubkeys, EthSpec, ExecutionBlockHash, ForkName, Hash256, SignedBeaconBlock,
    SignedExecutionPayloadBid, Slot,
};
use futures::future::join_all;
use sensitive_url::SensitiveUrl;
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use tracing::{debug, warn};

/// A validated direct builder bid, with the provenance and per-builder policy needed to turn it into
/// a selection candidate.
///
/// The per-builder `min_bid` / `max_execution_payment` / `builder_boost_factor` are carried up as-is;
/// this crate applies no bid math (the `min_bid` floor and the boost are proposer policy resolved on
/// the beacon-chain side).
#[derive(Clone)]
pub struct DirectBid<E: EthSpec> {
    /// The signed bid returned by the builder.
    pub signed_bid: Arc<SignedExecutionPayloadBid<E>>,
    /// URL of the builder that returned this bid, so a winning block can be forwarded to it via
    /// `submitSignedBeaconBlock` (echoed to the beacon node as `Eth-Builder-Url`).
    pub builder_url: SensitiveUrl,
    /// The proposer's `max_execution_payment` cap for this builder, from its `BuilderEntry`.
    pub max_execution_payment: u64,
    /// The proposer's `builder_boost_factor` for this builder, from its `BuilderEntry`.
    pub builder_boost_factor: u64,
    /// The proposer's `min_bid` acceptance floor (gwei) for this builder, from its `BuilderEntry`.
    pub min_bid: u64,
}

/// The per-proposal parameters used to address each `getExecutionPayloadBid` request.
///
/// Validation of returned bids is performed entirely by the caller's `validate` callback (which has
/// the beacon-chain state), so this only carries what's needed to build the request.
#[derive(Clone)]
pub struct BidRequestContext {
    pub slot: Slot,
    /// The latest executed ancestor's payload hash (the parent's payload when building on FULL,
    /// otherwise the payload the parent built on). Sent as the builder API's `parent_hash` path
    /// parameter, and the hash a returned bid must name as its `parent_block_hash`.
    pub executed_ancestor_hash: ExecutionBlockHash,
    pub parent_root: Hash256,
    pub proposer_pubkey: PublicKeyBytes,
    /// The active consensus version at `slot`, sent as the required `Eth-Consensus-Version`
    /// header on each bid request.
    pub fork_name: ForkName,
}

/// Orchestrates direct builder bid requests.
///
/// Fans `getExecutionPayloadBid` out to the builders a proposer configured and returns the validated
/// bids for the block producer to rank against the local and gossip payloads. Stateless — it holds
/// no bids between requests.
pub struct Builders {
    client: Arc<BuilderHttpClient>,
}

/// A single failed builder-preference submission, identified by its position in the submitted list.
pub struct SubmissionFailure {
    /// Index of the failing entry in the submitted list.
    pub index: usize,
    /// Why the submission failed.
    pub error: BuilderClientError,
}

impl Builders {
    pub fn new(client: Arc<BuilderHttpClient>) -> Self {
        Self { client }
    }

    /// Forward a signed beacon block to the builder that won this slot's bid, via
    /// `submitSignedBeaconBlock`.
    ///
    /// Submitted as JSON: the builder's SSZ preference from bid time isn't carried across the
    /// `Eth-Builder-Url` header round-trip, and builders must accept JSON.
    pub async fn forward_signed_block<E: EthSpec>(
        &self,
        builder_url: &SensitiveUrl,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), BuilderClientError> {
        self.client
            .submit_signed_beacon_block(builder_url, block, false)
            .await
    }

    /// Request bids from every builder in `entries` concurrently, validate them, and return the
    /// valid ones.
    ///
    /// Every entry is a bid request to its `url`, which beacon-APIs #630 requires (a zero-length url
    /// is invalid); an entry whose `url` is empty, malformed, or not http(s) can't be requested and
    /// is skipped. One request is made **per entry** — several entries MAY share a `url` with
    /// different `auth`, so requests are not de-duplicated by URL (#630 forbids two entries sharing
    /// both a `url` and their `auth`'s `data`).
    ///
    /// Each builder runs in its own pipeline — request, then the producer-supplied `validate`
    /// callback, which performs *all* bid validation against the block producer's advanced beacon
    /// state (consensus consistency, builder eligibility, collateral, and the BLS signature). The
    /// entry's `builder_pubkeys` filter (empty accepts any builder) is passed to `validate` so it
    /// can enforce that the bid is signed by one of the expected builders — the state and signing
    /// domain that check needs live on the producer side, not here. The per-builder `min_bid` floor
    /// is likewise a proposer policy applied by the caller (see `DirectBid::min_bid`), not here. These
    /// pipelines run
    /// **concurrently across builders**, so a slow builder or an expensive validation for one bid
    /// does not hold up the others. A failure, timeout, empty (204) response, or validation error
    /// for one builder is isolated: it is logged and that bid is skipped.
    ///
    /// Returns every bid that passed validation; the block producer turns each into a selection
    /// candidate and ranks them.
    pub async fn request_and_validate_bids<E: EthSpec, F, Fut, Err>(
        &self,
        ctx: &BidRequestContext,
        entries: &[BuilderEntry],
        validate: F,
    ) -> Vec<DirectBid<E>>
    where
        F: Fn(Arc<SignedExecutionPayloadBid<E>>, BuilderPubkeys) -> Fut,
        Fut: Future<Output = Result<(), Err>>,
        Err: Display,
    {
        // Resolve each entry to a `(resolved_url, entry)` target. Every entry must carry a valid url
        // (#630); one that's empty, malformed, or non-http(s) can't be requested and is skipped. One
        // request is made per entry (no URL de-duplication).
        let mut targets = Vec::new();
        for entry in entries {
            let url = match entry.url.to_sensitive_url() {
                Ok(url) => url,
                Err(e) => {
                    warn!(error = ?e, "Skipping builder entry with a malformed URL");
                    continue;
                }
            };
            if !matches!(url.expose_full().scheme(), "http" | "https") {
                warn!(url = ?url, "Skipping builder entry with an unsupported URL scheme");
                continue;
            }
            targets.push((url, entry));
        }

        // Run one pipeline per builder — request, then the producer's `validate` callback — and let
        // them run concurrently across builders. Each request carries its own timeout, so a slow
        // builder cannot delay the others.
        let client = &self.client;
        let validate = &validate;
        let pipelines = targets.iter().map(|(url, entry)| async move {
            let response = client
                .get_execution_payload_bid::<E>(
                    url,
                    ctx.slot,
                    ctx.executed_ancestor_hash,
                    ctx.parent_root,
                    &ctx.proposer_pubkey,
                    &entry.auth,
                    ctx.fork_name,
                )
                .await;

            match response {
                Ok(Some(bid)) => {
                    let direct_bid = DirectBid {
                        signed_bid: Arc::new(bid),
                        builder_url: url.clone(),
                        max_execution_payment: entry.max_execution_payment,
                        builder_boost_factor: entry.builder_boost_factor,
                        min_bid: entry.min_bid,
                    };

                    if let Err(error) =
                        validate(direct_bid.signed_bid.clone(), entry.builder_pubkeys.clone()).await
                    {
                        warn!(url = ?url, %error, "Builder bid failed validation");
                        return None;
                    }
                    Some(direct_bid)
                }
                Ok(None) => {
                    debug!(url = ?url, "Builder returned no bid");
                    None
                }
                Err(error) => {
                    warn!(url = ?url, error = %error, "Builder bid request failed");
                    None
                }
            }
        });

        join_all(pipelines).await.into_iter().flatten().collect()
    }

    /// Submit a proposer's builder preferences to each entry's builder, concurrently and
    /// best-effort.
    ///
    /// One submission is made per entry — entries are **not** de-duplicated by URL, since
    /// beacon-APIs #630 allows several entries to share a `url`. Each submission is isolated: a
    /// malformed URL or a failed request is recorded against that entry's index and never aborts the
    /// others. The submissions run **concurrently**, so a slow builder cannot delay the rest.
    ///
    /// Returns `Ok(())` when every entry was submitted, or the per-entry [`SubmissionFailure`]s by
    /// index.
    pub async fn submit_builder_preferences(
        &self,
        entries: Vec<BuilderPreferenceEntry>,
        fork_name: ForkName,
    ) -> Result<(), Vec<SubmissionFailure>> {
        let client = &self.client;
        let submissions = entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| async move {
                let url = entry
                    .url
                    .to_sensitive_url()
                    .map_err(|e| SubmissionFailure {
                        index,
                        error: e.into(),
                    })?;
                let request = BuilderPreferencesRequest::new(
                    BuilderPreferences {
                        max_execution_payment: entry.max_execution_payment,
                    },
                    entry.auth,
                );
                client
                    .submit_builder_preferences(&url, &entry.proposer_pubkey, &request, fork_name)
                    .await
                    .map_err(|error| SubmissionFailure { index, error })
            });

        let failures: Vec<SubmissionFailure> = join_all(submissions)
            .await
            .into_iter()
            .filter_map(Result::err)
            .collect();

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;
    use eth2::types::beacon_response::EmptyMetadata;
    use eth2::types::{
        ExecutionPayloadBid, ForkName, ForkVersionedResponse, MainnetEthSpec, RequestAuth,
        RequestAuthData, SignedExecutionPayloadBid, SignedRequestAuth,
    };
    use eth2::{CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER};
    use mockito::{Matcher, Mock, Server, ServerGuard};

    type E = MainnetEthSpec;

    const BID_PATH: &str = r"^/eth/v1/builder/execution_payload_bid/.+$";

    fn entry(url: &str, max_execution_payment: u64) -> BuilderEntry {
        BuilderEntry {
            url: url.parse().unwrap(),
            auth: SignedRequestAuth {
                message: RequestAuth {
                    data: RequestAuthData::new(url.as_bytes().to_vec()).unwrap(),
                    slot: Slot::new(1),
                },
                signature: Signature::empty(),
            },
            builder_pubkeys: BuilderPubkeys::default(),
            max_execution_payment,
            min_bid: 0,
            builder_boost_factor: 100,
        }
    }

    fn bid_body(value: u64) -> String {
        let body = ForkVersionedResponse {
            version: ForkName::Gloas,
            metadata: EmptyMetadata {},
            data: SignedExecutionPayloadBid::<E> {
                message: ExecutionPayloadBid {
                    slot: Slot::new(1),
                    parent_block_hash: ExecutionBlockHash::zero(),
                    parent_block_root: Hash256::ZERO,
                    value,
                    ..ExecutionPayloadBid::default()
                },
                signature: Signature::empty(),
            },
        };
        serde_json::to_string(&body).unwrap()
    }

    fn mock_bid(server: &mut ServerGuard, value: u64) -> Mock {
        server
            .mock("POST", Matcher::Regex(BID_PATH.to_string()))
            .with_header(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE_HEADER)
            .with_header(CONSENSUS_VERSION_HEADER, "gloas")
            .with_body(bid_body(value))
            .with_status(200)
            .create()
    }

    fn context() -> BidRequestContext {
        BidRequestContext {
            slot: Slot::new(1),
            executed_ancestor_hash: ExecutionBlockHash::zero(),
            parent_root: Hash256::ZERO,
            proposer_pubkey: PublicKeyBytes::empty(),
            fork_name: ForkName::Gloas,
        }
    }

    fn builders() -> Builders {
        Builders::new(Arc::new(BuilderHttpClient::new(None, false).unwrap()))
    }

    #[tokio::test]
    async fn fans_out_and_returns_all_valid_bids() {
        let mut server_a = Server::new_async().await;
        let mut server_b = Server::new_async().await;
        mock_bid(&mut server_a, 100);
        mock_bid(&mut server_b, 200);

        let builders = builders();
        let entries = vec![entry(&server_a.url(), 1000), entry(&server_b.url(), 1000)];

        let bids: Vec<DirectBid<E>> = builders
            .request_and_validate_bids(&context(), &entries, |_bid, _expected| async {
                Ok::<(), String>(())
            })
            .await;
        let mut values: Vec<u64> = bids.iter().map(|b| b.signed_bid.message.value).collect();
        values.sort_unstable();
        assert_eq!(values, vec![100, 200]);
    }

    #[tokio::test]
    async fn skips_invalid_url_entry() {
        let builders = builders();
        // #630 requires a url; an empty one is invalid and can't be requested, so it is skipped.
        let entries = vec![entry("", 1000)];

        let bids: Vec<DirectBid<E>> = builders
            .request_and_validate_bids(&context(), &entries, |_bid, _expected| async {
                Ok::<(), String>(())
            })
            .await;
        assert!(bids.is_empty());
    }

    #[tokio::test]
    async fn requests_each_entry_even_when_url_is_shared() {
        let mut server = Server::new_async().await;
        // Two entries share a URL but carry different `auth`, so both are requested (one per entry).
        let mock = mock_bid(&mut server, 100).expect(2);

        let builders = builders();
        let entry_a = entry(&server.url(), 1000);
        let mut entry_b = entry(&server.url(), 1000);
        entry_b.auth.message.slot = Slot::new(2);
        let entries = vec![entry_a, entry_b];

        let bids: Vec<DirectBid<E>> = builders
            .request_and_validate_bids(&context(), &entries, |_bid, _expected| async {
                Ok::<(), String>(())
            })
            .await;
        assert_eq!(bids.len(), 2);
        mock.assert();
    }

    #[tokio::test]
    async fn returns_bid_carrying_min_bid_for_the_caller() {
        // The transport layer does not enforce the `min_bid` floor: it returns the bid carrying its
        // entry's `min_bid` for the beacon-chain-side caller to enforce.
        let mut server = Server::new_async().await;
        mock_bid(&mut server, 100);

        let builders = builders();
        let mut entry = entry(&server.url(), 1000);
        entry.min_bid = 500;
        let entries = vec![entry];

        let bids: Vec<DirectBid<E>> = builders
            .request_and_validate_bids(&context(), &entries, |_bid, _expected| async {
                Ok::<(), String>(())
            })
            .await;
        assert_eq!(bids.len(), 1);
        assert_eq!(bids[0].min_bid, 500);
    }

    #[tokio::test]
    async fn rejects_bid_failing_producer_validation() {
        let mut server = Server::new_async().await;
        mock_bid(&mut server, 100);

        let builders = builders();
        let entries = vec![entry(&server.url(), 1000)];
        // The producer callback rejects the bid (e.g. a failed signature or ineligible builder).
        let bids: Vec<DirectBid<E>> = builders
            .request_and_validate_bids(&context(), &entries, |_bid, _expected| async {
                Err::<(), String>("rejected by producer".to_string())
            })
            .await;
        assert!(bids.is_empty());
    }
}

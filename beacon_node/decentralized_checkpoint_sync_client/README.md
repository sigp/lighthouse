# HTTP light-client checkpoint consumer

Fetch untrusted light-client data and return a recent authenticated finalized header, without
an existing `BeaconChain`, database or private Tokio runtime. The `decentralized_checkpoint_sync`
core verifies bootstrap proofs, committee continuity, updates and finality. The client only
orchestrates those operations with explicit freshness and resource limits.

```text
trusted finalized block root + trusted network context + local clock
  -> verified bootstrap -> authenticated committee updates -> recent verified finalized header
```

This is header synchronization, not block forward sync or a complete checkpoint startup.
State/block download, state-summary authentication, P2P parts and startup wiring are separate work.

## Trust and usage

The caller supplies the trusted **finalized** root, the correct `ChainSpec`, genesis validators
root and a `SlotClock` initialized from trusted genesis time. This library does not establish the
root's finality or weak-subjectivity suitability. Do not discover these trust inputs from the same
untrusted provider. A provider must retain the requested bootstrap and sufficient committee history;
even a correct provider may not be able to serve an arbitrarily old root.

Use the caller's Tokio runtime with time and I/O enabled. The following example is compiled as a
documentation test; it does not contact a public endpoint. Policy values are illustrative local
choices, not consensus requirements or recommended defaults for every network.

```no_run
use decentralized_checkpoint_sync_client::{
    HttpLightClientDataSource, RequestLimits, SyncOutcome, SyncPolicy,
    sync_verified_finalized_header,
};
use eth2::SensitiveUrl;
use slot_clock::SlotClock;
use std::{future::Future, sync::Arc, time::Duration};
use types::{ChainSpec, EthSpec, Hash256};

async fn obtain_checkpoint_header<E: EthSpec>(
    provider: SensitiveUrl,
    trusted_finalized_root: Hash256,
    spec: Arc<ChainSpec>,
    genesis_validators_root: Hash256,
    clock: &impl SlotClock,
    shutdown: impl Future<Output = ()>,
) -> Result<Option<SyncOutcome<E>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut source = HttpLightClientDataSource::new(provider)?;
    let policy = SyncPolicy {
        max_finalized_lag_slots: 128,
        max_updates_per_request: 8,
        request_limits: RequestLimits::new(Duration::from_secs(10), 1_048_576)?,
        sync_timeout: Duration::from_secs(120),
        max_requests: 32,
        max_updates: 256,
        max_total_response_bytes: 16_777_216,
        max_no_progress_requests: 4,
        max_retries: 2,
        initial_retry_delay: Duration::from_millis(100),
        max_retry_delay: Duration::from_secs(2),
    };
    tokio::select! {
        biased;
        _ = shutdown => Ok(None), // Only this wrapper's explicit cancellation returns None.
        result = sync_verified_finalized_header::<E>(
            &mut source, trusted_finalized_root, spec, genesis_validators_root, clock, &policy,
        ) => Ok(Some(result?)),
    }
}
```

Success returns the core's `VerifiedFinalizedHeader` and charged request/update/body-byte usage.
It never substitutes an optimistic or timeout-forced header. Freshness is checked against the local
clock at return time; recheck it if handoff is delayed. The HTTP adapter preserves fork metadata and
does not authenticate data itself. Only the core may construct an authenticated header.

Only transient transport failures and selected HTTP statuses are retried within budget. Missing
history (`Unavailable`), malformed/oversized responses and core verification failures are terminal,
distinct errors. Empty/replayed/minority-only responses cannot create indefinite progress. Clock
errors, unsupported local forks, no progress, retry exhaustion and budget/deadline exhaustion are
errors, not a stale-success fallback. Unknown wire forks fail decoding as `InvalidData`, with the
original bounded HTTP error retained; the adapter does not guess the fork from error text.

Dropping the synchronization future cancels pending I/O/backoff and stops further scheduling. An
already running blocking decoder/verifier can finish, but has bounded input and private state; it
cannot publish a late checkpoint. If an individual request times out before its source reports
partial bytes, the driver conservatively charges its full request allowance. Dropping the whole
task does not return usage. Cloned HTTP sources share the transport's single-request permit; they
do not bypass its worker bound.

## Future Lighthouse startup handoff

The intended caller is `ClientBuilder::beacon_chain_builder` in `beacon_node/client/src/builder.rs`,
before calling `BeaconChainBuilder::weak_subjectivity_state`. That caller already has the chain spec
and `RuntimeContext`; it can race this future against `context.executor.exit()` rather than creating
a second runtime. The configured network genesis state must supply genesis time and validators root.
The existing `system_time_slot_clock` helper requires an initialized beacon-chain builder, so this
earlier phase must construct its clock from trusted genesis information first.

The returned header is **not** yet the input to `weak_subjectivity_state`. A following stage must
obtain and verify a complete state against `header.beacon_state_root()`, and a matching signed block
against `header.beacon_block_root()`. The builder may advance the state to an epoch boundary; root
authentication must happen before that mutation. Its existing latest-block/genesis checks remain
necessary but do not replace authentication against the light-client header. Summary/parts retrieval
is another way to obtain that state, not functionality of this crate. No existing startup behavior or
CLI changes here.

## Test boundaries

- `tests/source.rs` and `tests/consumer/`: orchestration, clock/fork transitions, atomic candidate
  processing, retries, budgets and cancellation with a scripted source and real cryptography.
- `tests/http.rs`: adapter classification, fork metadata and byte accounting.
- `tests/http_sync.rs`: local HTTP through the real core, including adversarial responses and
  Minimal/Mainnet committee shapes, reusing the same signing fixture.
- `common/eth2/tests/light_client.rs`: bounded wire reads, malformed/chunked/error bodies,
  content types, redirects and request timeouts. These transport tests are not duplicated here.
- `beacon_node/http_api/tests/light_client_consumer_tests.rs`: actual Lighthouse harness/server
  interoperability, using fixed signed block events through the production LC cache entry point.
  It checks available data with non-genesis finality across fork schemas, not genesis-update
  production, cache production at every transition slot, historical backfill completeness, or a
  public provider's data availability.

These tests do not replace the core's official EF conformance tests, nor claim to validate full
Lighthouse checkpoint startup. No default test accesses a public network.

Run the client tests (including the compiled example) with
`cargo test -p decentralized_checkpoint_sync_client`. The real server test belongs to the existing
release-only HTTP suite:
`cargo test --release -p http_api --test bn_http_api_tests light_client_consumer`.

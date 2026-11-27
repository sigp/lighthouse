# Common PQ measurements

This crate exports `pq.measurement/0.1` as dedicated OTLP/gRPC structured logs. It instruments existing work; enabling it does not add subnet subscriptions or synthetic validator duties. Ordinary logs, tracing and the local observation-node experiments are independent.

## Enable collection

Add these flags to the existing beacon-node **and** validator-client commands:

```text
--pq-measurement-otlp-endpoint http://otel-collector:4317
--pq-measurement-node-id lighthouse-1
```

Use the same stable, operator-assigned node ID for an associated BN and VC. `PQ_MEASUREMENT_NODE_ID` can supply the ID instead of the second flag. An explicit flag takes precedence. A separate process UUID is generated at each process start, so a restart cannot collide with earlier records. Omit the endpoint flag to disable this collection; no separate enable flag is needed.

The endpoint requires an explicit `http://` (plaintext) or `https://` (TLS) scheme, host and port. Root `/` is permitted; credentials, other paths, query strings and fragments are rejected at startup. An unavailable collector does not prevent node startup. HTTPS verifies the server using platform trust roots. This exporter does not provide an inline credential or client-certificate flag; deploy an appropriately configured local Collector when the remote service requires custom authentication or mTLS. No ordinary OpenTelemetry log/trace environment settings implicitly enable this dedicated stream.

`PQ_MEASUREMENT_HARDWARE_REF` may name a deployment metadata record describing CPU model, CPU allocation/quota/affinity, memory limit and native/emulated execution. If omitted, the exported reference explicitly declares those details unavailable. The context's `metrics_node_ref` is `deployment:<node-id>`; deployments must map that identifier to existing host/Prometheus/Xatu selectors and validity intervals. Include host clock synchronization, offset and uncertainty in that mapping before interpreting cross-node wall-clock intervals.

`--pq-measurement` and `--pq-timing-output` are separate observer-experiment options. They are not required by this exporter. BN/VC duty correlation can use the implementation's optional HTTP telemetry metadata; telemetry does not change consensus messages or make successful HTTP submission count as gossip publication.

## Export and loss behavior

The default queue holds at most 2,048 records, with a conservative per-body limit of 64 KiB and at most 32 records in an export batch. JSON bodies also have a nesting bound. Invalid/oversized records and full queues are dropped and counted, rather than blocking a validator duty. All ten event names have a fixed metric label set.

The worker uses a one-second flush interval and also flushes when a batch fills. Network attempts have a two-second timeout; a slow collector can delay this background worker without blocking duties. It sends homogeneous event-family requests, allowing a collector's partial rejection count to be attributed to the correct family. Failed requests are counted as dropped/unconfirmed delivery and are not retried indefinitely. A timeout can mean a collector accepted data before losing its response; collectors must deduplicate `(process_id, event_seq)`.

The immutable context is generated once and replayed before batches with its original identity. Replays do not increase the logical generated counter. This lets a reconnecting collector recover context without inventing a new process or rewriting event identities. Records can arrive out of order; consumers resolve explicit references rather than assuming transport ordering.

These process-cumulative counters are exposed through Lighthouse's existing Prometheus registry:

| Metric | Meaning |
| --- | --- |
| `pq_measurement_generated_total{event}` | Logical records created before queue admission; excludes context replays. |
| `pq_measurement_dropped_total{event}` | Queue/shape losses and rejected or unconfirmed exported records. |
| `pq_measurement_summary_evictions_total{event}` | Bounded correlation/summary observations lost. |
| `pq_measurement_export_errors_total` | Failed or partially rejected export requests. |

Enable the existing metrics HTTP endpoint separately if Prometheus will scrape these counters. Collector/router rejection and storage losses need their own monitoring. Missing completions do not imply success, failure or zero duration.

## Timing and coverage

Hooks take paired UTC/monotonic timestamps before enriching their record. Monotonic differences are valid only within the same process UUID. The context describes the actual receipt, validation, pool, publication and backend boundaries. Native execution duration includes internal backend locking; it is not CPU utilization. The canonical body remains a nested OTLP map, including exact decimal-string nanoseconds, with no TraceId/SpanId requirement.

The beacon node counts complete compressed aggregate payload copies using the optional observer in `ethDreamer/rust-libp2p@5f32482bf2ac5519f3def8f92af1c567c26fefdc`, pinned consistently for libp2p and mplex. RX runs before graylisting, decompression and deduplication over both decoded-valid and decoded-invalid publish entries. TX runs only after each peer queue accepts a complete payload, including forwarding and IWANT repeats. Empty payloads are zero-byte copies. Whole frames rejected before topic/payload decoding are outside the attributed scope. Later expiry, IDONTWANT removal or transport failure does not subtract a successful TX handoff. These are payload-copy counters, **not NIC bytes or delivery acknowledgements**; protobuf/control framing, encryption and retransmissions are excluded.

Only configured PQ aggregate topics are allowlisted. Ten half-open 100 ms buckets form each one-second record. Callbacks advance bucket assignment even if the timer is delayed; the one-second timer exports completed windows, including observed zeros. The observer captures one paired UTC/monotonic anchor at startup. Nominal boundary UTC labels use that fixed offset throughout its lifetime, without claiming an actual clock read at each boundary or silently re-anchoring after wall-clock steps. Other event timestamps remain actual clock readings. Host clock metadata is required to assess cross-node uncertainty.

Storage and catch-up work are bounded. Overflow or lost observation is marked `not_observed`; evicted windows increment measurement-health counters. Collector/exporter loss must never be interpreted as zero traffic. Shutdown submits only completed windows; the unfinished window stays unknown. Copy hooks do not serialize events, recompress/hash payloads, or wait for export. The timer and gossip callbacks share the network polling task. The VC has no gossip traffic scope. Omitting the common endpoint flag installs no traffic observer or timer.

## Tests

```sh
cargo check -p pq_measurement
PQ_MEASUREMENT_TEST_CAPTURE=/tmp/pq-export.json \
PQ_MEASUREMENT_HOOK_CAPTURE=/tmp/pq-hooks.json \
cargo test -p pq_measurement --lib
```

Collector tests bind an ephemeral loopback TCP port. They test real tonic LogsService encoding, failures, recovery and partial rejection, plus bounded queues, restart IDs, clocks and traffic-bucket accounting. The global lifecycle test exercises actual instrumentation helpers with synthetic inputs; it does not run real proofs or certify cross-client interoperability.

To validate reconstructed captures independently, install `jsonschema` in a test virtual environment and run from this crate's directory:

```sh
python tests/validate_capture.py /tmp/pq-export.json /tmp/pq-hooks.json
```

The schema and examples in `tests/fixtures` are copied from `ethDreamer/pq-measurement-spec` commit `1effe59`. All published examples are also round-tripped losslessly through the OTLP mapping in the Rust tests. Hook tests check successful, rejected, deferred, cancelled, committee, multi-call, backend-failure and reusable/hybrid paths. Source-hook coverage still needs a live pilot with normal host metrics and exporter-off/on comparisons.

A separately invoked release microbenchmark measures the disabled lookup and enabled timestamp/JSON/reference/enqueue path:

```sh
cargo test -p pq_measurement --release measure_hook_path_overhead -- --ignored --nocapture
cargo test -p pq_measurement --release measure_complete_copy_callback_overhead -- --ignored --nocapture
```

It deliberately excludes background serialization/export, real proving, and full-node concurrency. It is a hook-cost check, not a production throughput or overhead guarantee.

## Fallback-node ambiguity

The optional bounded `x-lighthouse-pq-measurement` HTTP header carries duty references over existing VC/BN requests. Committee subscriptions carry the owner before proving starts; proposer preparation and aggregate submissions carry the same references. The BN records the real libp2p result against that owner. Invalid or oversized metadata does not fail the duty request, and overflow is counted as measurement loss. A header received after work was admitted cannot rewrite that operation's historical owner.

A VC HTTP timeout does not prove publication failed: the first BN may have published before its response was lost. A fallback BN can then independently publish or suppress an already-covered aggregate. Consequently, different BNs can report different terminal observations for the same duty reference. Preserve their emitting process IDs and source timestamps; flag the duty as multiply observed or ambiguous rather than choosing a global order or counting it as several duties. No global completion ordering or cross-BN exactly-once guarantee is claimed.

VC signing failures are attributed only after normal stream completion, to requested validator identities that never yielded a signed output. Successfully signed identities are removed before HTTP submission, so publication timeouts are not misclassified as signing failures. Interrupted streams remain unknown. Duty changes are closed by the VC only before the old publication cutoff; a later refresh must not invent another outcome for a possibly published duty.

The proposal service records known failures before block submission: VRF/signing failures, exhausted block-fetch attempts, invalid returned block/envelope pairs, removed signing keys and expired duty notifications. Block-publication HTTP errors and errors publishing a later execution envelope do not retroactively turn a potentially published proposal into a failure.

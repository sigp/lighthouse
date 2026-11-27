# PQ minimal reference results

Run requested by jtraglia: [consensus-specs Actions 45914857891](https://github.com/ethereum/consensus-specs/actions/runs/45914857891).
Spec revision: `b73c6956b086e06b45158553f571106ef6c47eba`, branch `pq`.
Lighthouse review base: `2eb616dfe96fb98dd841b11282b25c80b53a8452`, plus the fixes accompanying this report.

Artifact `minimal.tar.gz`, ID `15169131153`, 107,779,539 bytes, SHA-256:
`9df7501535febfdcd991a024a4230ec62c92b0dc27416e30cc3d047cef1bbd6d`.
The downloaded response is directly a gzip/tar payload, despite the `/zip` API endpoint.
Generation and packaging succeeded. Only the coverage job's `Combine coverages` step failed;
that failure was explicitly excluded from the request.

```sh
gh api repos/ethereum/consensus-specs/actions/artifacts/15169131153/zip > minimal.tar.gz
shasum -a 256 minimal.tar.gz
mkdir pq-reference-artifact
tar -xzf minimal.tar.gz -C pq-reference-artifact
```

Use the commands in [README.md](README.md#explicit-pq-reference-artifacts), selecting this
extracted directory. The original installed reference release is not overwritten.
Run real and fake-BLS state targets, fake-BLS SSZ, and real/fake-BLS networking.
Network tests require a local mock execution endpoint. Real and fake results are merged
by case identity; skips and unsupported cases are never counted as passes.

## Results

All **8,657 manifest cases** are accounted for. **7,673 pass**. This is not an all-green
conformance result. Nonzero exits are retained for unresolved failures.

| Runner | Passed | Failed or load error | Unsupported | Skipped |
| --- | ---: | ---: | ---: | ---: |
| epoch_processing | 167 | 0 | 0 | 0 |
| fast_confirmation | 0 | 0 | 0 | 157 |
| finality | 5 | 0 | 0 | 0 |
| fork | 0 | 15 | 0 | 0 |
| fork_choice | 82 | 0 | 0 | 0 |
| networking | 117 | 130 | 0 | 19 |
| operations | 409 | 7 | 24 | 0 |
| random | 0 | 16 | 0 | 0 |
| rewards | 45 | 0 | 0 | 1 |
| sanity | 83 | 0 | 0 | 0 |
| ssz_static | 6,765 | 246 | 369 | 0 |
| **Total** | **7,673** | **414** | **393** | **177** |

The remaining cases have different causes:

- **Client type mismatch:** 246 partial-column metadata/sidecar SSZ cases serialize and
  decode correctly but have different roots. The spec uses `ProgressiveBitList`; native
  `CellBitmap` is still bounded `BitList`, shared with Fulu. Correcting it needs fork-aware
  type/root handling, not a global replacement that changes Fulu.
- **Client feature scope:** 24 standalone preregistration/voluntary-exit request cases are
  unsupported. Seven parent-payload cases fail on the client's explicit rejection of
  those requests. These devnet contract paths have no implementation.
- **Pre-fork compatibility:** 15 fork-upgrade cases cannot decode the legacy pre-state
  because this PQ-only devnet changed Validator/Builder layouts across legacy forks.
- **Harness adapters:** 123 gossip cases need six missing topic adapters, and seven need
  setup-payload metadata support. Their load errors do not establish a client failure.
  Another 369 SSZ cases reference absent native helper types: Eth1Block, PowBlock, MatrixEntry.
- **Fake-XMSS fixtures:** the 157 fast-confirmation fixtures disable both BLS and XMSS in
  their generator and are explicitly skipped. The 16 random fixtures were attempted in
  fake-BLS mode but fail proposal-signature checks for the same reason. Lighthouse's
  existing fake-crypto mode disables BLS only. No production XMSS bypass was added.
- **Existing harness skips:** 19 gossip anchor/history/timing cases and one genesis-epoch
  rewards case remain explicitly skipped.

## Fixes validated by this run

- Legacy deposit XMSS IDs and VRF commitments use Keccak-256, as required by the pinned spec.
- Observed-aggregate subset/superset checks require equal signer-bitfield lengths, so malformed
  shorter bitfields reach validation instead of being ignored as duplicates.
- Unknown PQ proposer indices produce gossip Reject rather than an internal error mapped to Ignore.
- A native PQ NewPayloadRequest SSZ helper includes PQ execution requests, preserving the
  existing Gloas helper and separate runtime Engine API representation.

The adapters now decode PQ operations, slashings, gossip, and fork-choice envelopes/votes;
respect crypto metadata; and classify malformed wire SSZ as Reject without hiding file errors.

Validation: Lighthouse/LCLI cargo check; real and fake-BLS reference targets; SSZ/network
cargo checks; deposit identity unit test (1 pass); observed-aggregate regression tests
(2 passes); formatting and diff checks. No image was published and no enclave was changed.

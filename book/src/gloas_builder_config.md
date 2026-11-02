# Builder Configuration

> This applies from the **Gloas** fork onwards. It configures how the validator client sources
> execution-payload bids from external builders under ePBS.

The validator client reads its external-builder settings from a YAML file named
`builder_definitions.yml` in the validator directory
(`<datadir>/validators/builder_definitions.yml`). The file contains:

- **A global bid policy** — `min_bid` and `builder_boost_factor`, applied to bids received over p2p
  (gossip) and used as the default for any builder that does not set its own.
- **A list of builders** to request bids from directly, each with optional per-builder overrides of
  the global policy.
- **Per-validator configurations** under `validator_configs`, managed through the standard keymanager
  API. Each map key is a validator public key.

Use `GET`, `POST`, and `DELETE` at `/eth/v1/validator/{pubkey}/builder_config`. `GET` returns the
configuration in use. `POST` replaces the stored configuration. `DELETE` restores global inheritance.

## Example

```yaml
# Global bid policy: applies to p2p (gossip) bids, and is the default for any
# builder below that omits the corresponding field.
min_bid: 0                    # gwei — bids below this rank last; one wins only if nothing else is viable
builder_boost_factor: 100     # percent — 100 = neutral, >100 favors builders, 0 = prefer local

builders:
  # Minimal builder — inherits the global policy.
  - enabled: true
    url: "https://builder-a.example.com"
    max_execution_payment: 1000000000   # gwei — cap on the trusted execution payment

  # Builder overriding the globals and pinning the expected builder key.
  - enabled: true
    url: "https://builder-b.example.com"
    max_execution_payment: 1000000000
    min_bid: 500000000                  # override the global for this builder
    builder_boost_factor: 120           # override the global for this builder
    builder_pubkeys:                    # optional — reject a bid not signed by one of these keys
      - "0xa1b2c3d4..."
    # auth_data: "0x6275696c..."        # optional — defaults to the hostname of `url`

# Optional per-validator configuration.
# validator_configs:
#   "0x<validator-public-key>":
#     min_bid: 500000000
#     builders: []                 # explicitly disable direct builders for this validator
```

> **Comments are not preserved.** The validator client rewrites this file when builder settings
> change through the keymanager API. Keep an annotated copy elsewhere if you rely on inline notes.

## Fields

### Top level (global bid policy)

| Field | Required | Default | Meaning |
| ------- | ---------- | --------- | --------- |
| `min_bid` | no | `0` | Minimum total payment, in gwei, for a p2p bid. A bid below the floor is ranked behind any floor-clearing candidate (including the local block) and only wins when nothing else is viable. Also the default `min_bid` for any builder that omits it. |
| `builder_boost_factor` | no | `100` | Percentage multiplier applied to p2p bids when comparing against the local block. Also the default for any builder that omits it. |
| `builders` | no | `[]` | The list of builders to request bids from directly. |
| `validator_configs` | no | `{}` | Builder settings for individual validators. Omitted fields use global values. An empty `builders` list uses no direct builders. |

### Per builder (each entry under `builders`)

| Field | Required | Default | Meaning |
| ------- | ---------- | --------- | --------- |
| `enabled` | **yes** | — | Whether this builder is used. Disabled builders are ignored. |
| `url` | **yes** | — | The builder's `http`/`https` URL. Bids are requested from here at block-production time. |
| `max_execution_payment` | **yes** | — | Cap, in gwei, on the *trusted* execution payment accepted from this builder. |
| `min_bid` | no | *(global)* | Override the global minimum bid for this builder. |
| `builder_boost_factor` | no | *(global)* | Override the global boost factor for this builder. |
| `builder_pubkeys` | no | *(empty)* | The builder's BLS public keys, hex-encoded. If non-empty, a returned bid **not** signed by one of them is rejected. |
| `auth_data` | no | *(hostname of `url`)* | Opaque authentication data, hex-encoded, agreed with the builder out of band. Signed into the request. Must be non-empty when set. Defaults to the lowercase ASCII hostname of `url`. |

All byte fields (`builder_pubkeys` entries, `auth_data`) are `0x`-prefixed hex strings. All payment values
(`min_bid`, `max_execution_payment`) are in gwei.

The default `auth_data` excludes the scheme, credentials, port, path, query and fragment of the URL.
For example, both `https://builder.example.com` and `https://builder.example.com/` use
`builder.example.com`. An internationalized hostname must use punycode. IPv6 addresses use compressed,
bracketed hexadecimal form, such as `[::1]` or `[::ffff:c000:201]`.

A builder that uses a different identity must agree explicit `auth_data` with the validator operator.
Explicit values are signed exactly as configured. See the
[default authentication data specification](https://github.com/ethereum/builder-specs/pull/168).

## How bids are selected

At block-production time the validator client requests a bid from each enabled builder with a `url`,
and also considers bids seen over p2p. For each candidate bid:

- **`min_bid`** — a bid whose total value is below the applicable `min_bid` is ranked behind any
  floor-clearing candidate (including the local block) rather than dropped, so it wins only when
  nothing else is viable (e.g. the local build failed). Direct builders use their own (or the
  inherited per-validator) value; p2p bids use the validator's `min_bid`.
- **`builder_boost_factor`** — the surviving bid's value is scaled by its boost factor
  (`boost × value ÷ 100`) before being compared against the locally-built block. A factor below
  `100` favors the local block; above `100` favors the builder; `0` always prefers local;
  `2^64 − 1` strongly favors the builder. The factor is a multiplier, not an absolute override, so a
  zero-value bid still ranks `0` and loses to any non-zero local block.
- **`max_execution_payment`** — bounds how much of a builder's (off-chain) execution payment counts
  toward its bid value. This applies only to direct builders; p2p bids carry no trusted execution
  payment.
- **`builder_pubkeys`** — for a direct builder, if non-empty, the returned bid must be signed by
  one of these keys or it is discarded.

The highest-value bid after these rules wins. Per-builder `min_bid`/`builder_boost_factor` apply
only to bids requested directly by URL. For p2p bids, per-validator defaults override the global values.

## Logs

This section provide new block proposal logs relevant to ePBS. It assumes the "happy path": if a block production is successful, what you should expect to see in Lighthouse logs.

### Beacon node during block production

With ePBS, during block production, the beacon node usually receives several bids from various sources. The beacon node selects the best bid and logs:

```text
INFO  Winning execution payload bid                 slot: 190, source: gossip, builder_index: 0, bid_value_gwei: 120765522, execution_payment_gwei: 0, payload_value_wei: 120765522000000000, runner_up_source: "direct", runner_up_payload_value_wei: "20865522000000000"
```

The fields are:

- `slot`: the slot of the block proposal
- `source`, to indicate where the bid comes from:
  - `local` - locally built (i.e. via the execution client)
  - `gossip` - via p2p gossip in the network
  - `direct` - from direct builder connection
- `builder_index`: the index of the builder registered on the beacon chain. If the `source` is `local`, the `builder_index` will be shown as 18446744073709551615.
- `bid_value_gwei`: the value of the trustless bid promised by the builder. If the `source` is `local`, this will always be 0.
- `execution_payment_gwei`: the trusted execution payment by the builder. If the `source` is `local` or `gossip`, this will always be 0.
- `payload_value_wei`: the total value of the bid.
- `runner_up_source`: the source of the bid for the runner-up bid
- `runner_up_payload_value_wei`: the total value of the runner-up bid

Additionally, all bid candidates will be logged at the debug level:

```text
DEBUG Execution payload bid candidate               slot: 190, source: direct, builder_index: 2, bid_value_gwei: 14605866, execution_payment_gwei: 6259656, payload_value_wei: 20865522000000000
DEBUG Execution payload bid candidate               slot: 190, source: gossip, builder_index: 0, bid_value_gwei: 120765522, execution_payment_gwei: 0, payload_value_wei: 120765522000000000
DEBUG Execution payload bid candidate               slot: 190, source: local, builder_index: 18446744073709551615, bid_value_gwei: 0, execution_payment_gwei: 0, payload_value_wei: 20765522000000000
```

### Beacon node after block production (payload envelope)

If a bid is won by a direct builder connection, the beacon node will forward the signed block to the builder:

```text
INFO  Forwarded signed block to winning builder     slot: 130, block_root: 0x..
```

The builder will then reveal the envelope. The beacon node can receive the envelope via gossip:

```text
INFO  New envelope received                         slot: 201, root: 0x..
```

If the block is locally built, the beacon node receives it via the HTTP API:

```text
INFO  Publishing signed execution payload envelope to network  slot: 120, beacon_block_root: 0x.., builder_index: 18446744073709551615
```

### Validator client without `--stateless-block-production` (default)

For an external winning bid (gossip or direct), the VC logs:

```text
INFO  Builder bid won; the builder reveals the payload envelope  slot: 190, builder_index: 0, validator_pubkey: 0x…
```

If a block is built locally, after the log "Successfully published block", it logs:

```text
INFO  Fetching execution payload envelope           slot: 116, beacon_block_root: 0x..
INFO  Received execution payload envelope, signing  slot: 116, beacon_block_root: 0x..
INFO  Signed execution payload envelope, publishing  slot: 116
INFO  Successfully published signed execution payload envelope  slot: 116, beacon_block_root: 0x..
```

### Validator client with `--stateless-block-production`

This only affects locally built blocks.

In stateless block production, the VC will request the full block contents from the beacon node: beacon block, execution payload envelope, blobs, and KZG proofs. This enables stateless operation where the validator client signs and publishes the envelope to multiple beacon nodes, instead of the only beacon node that builds the block. This is useful for DVT operators such as Anchor during block proposals.

As the envelope arrives together with the block, some logs in the previous section (default mode) will not be observed. Instead, you should see the logs:

```text
INFO  Signing locally built execution payload envelope  slot: 139, beacon_block_root: 0x..
INFO  Successfully published signed execution payload envelope  slot: 139, beacon_block_root: 0x..
```

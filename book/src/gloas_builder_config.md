# Builder Configuration

> This applies from the **Gloas** fork onwards. It configures how the validator client sources
> execution-payload bids from external builders under ePBS.

The validator client reads its external-builder settings from a YAML file named
`builder_definitions.yml` in the validator directory
(`<datadir>/validators/builder_definitions.yml`). The file holds two things:

- **A global bid policy** — `min_bid` and `builder_boost_factor`, applied to bids received over p2p
  (gossip) and used as the default for any builder that does not set its own.
- **A list of builders** to request bids from directly, each with optional per-builder overrides of
  the global policy.

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
    # auth_data: "0x68747470..."        # optional — defaults to the UTF-8 bytes of `url`
```

> **Comments are not preserved.** The validator client rewrites this file when builders are added or
> removed (for example via the keymanager API), which strips YAML comments. Keep an annotated copy
> elsewhere if you rely on inline notes.

## Fields

### Top level (global bid policy)

| Field | Required | Default | Meaning |
| ------- | ---------- | --------- | --------- |
| `min_bid` | no | `0` | Minimum total payment, in gwei, for a p2p bid. A bid below the floor is ranked behind any floor-clearing candidate (including the local block) and only wins when nothing else is viable. Also the default `min_bid` for any builder that omits it. |
| `builder_boost_factor` | no | `100` | Percentage multiplier applied to p2p bids when comparing against the local block. Also the default for any builder that omits it. |
| `builders` | no | `[]` | The list of builders to request bids from directly. |

### Per builder (each entry under `builders`)

| Field | Required | Default | Meaning |
| ------- | ---------- | --------- | --------- |
| `enabled` | **yes** | — | Whether this builder is used. Disabled builders are ignored. |
| `url` | **yes** | — | The builder's `http`/`https` URL. Bids are requested from here at block-production time. |
| `max_execution_payment` | **yes** | — | Cap, in gwei, on the *trusted* execution payment accepted from this builder. |
| `min_bid` | no | *(global)* | Override the global minimum bid for this builder. |
| `builder_boost_factor` | no | *(global)* | Override the global boost factor for this builder. |
| `builder_pubkeys` | no | *(empty)* | The builder's BLS public keys, hex-encoded. If non-empty, a returned bid **not** signed by one of them is rejected. |
| `auth_data` | no | *(UTF-8 of `url`)* | Opaque authentication data, hex-encoded, agreed with the builder out of band. Signed into the request. Must be non-empty when set. Defaults to the UTF-8 bytes of `url`. |

All byte fields (`builder_pubkeys` entries, `auth_data`) are `0x`-prefixed hex strings. All payment values
(`min_bid`, `max_execution_payment`) are in gwei.

## How bids are selected

At block-production time the validator client requests a bid from each enabled builder with a `url`,
and also considers bids seen over p2p. For each candidate bid:

- **`min_bid`** — a bid whose total value is below the applicable `min_bid` is ranked behind any
  floor-clearing candidate (including the local block) rather than dropped, so it wins only when
  nothing else is viable (e.g. the local build failed). Direct builders use their own (or the
  inherited global) value; p2p bids use the global value.
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
only to bids requested directly by URL; p2p bids are governed by the global values.

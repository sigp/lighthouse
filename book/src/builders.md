# MEV and Lighthouse

A primer on MEV can be found [here]([MEV](https://ethereum.org/en/developers/docs/mev/)).

Lighthouse is able to interact with servers that implement the [builder API](https://github.com/ethereum/builder-specs). 
If the builder you are connected to 

## How to connect to a builder

The beacon node and validator client each require a new flag for lighthouse to be fully compatible with builder API servers.
It's important that the builder API server you are connected to is serving informatoin about 

```
lighthouse bn --builder https://mainnet-builder.test
```

```
lighthouse vc --builder-proposals
```

## Multiple builders

Run MEV-boost to multiplex builder connections.

* [`mev-boost`][mev-boost]
* [`mev-rs`][mev-rs]

## Fallback to local

- `--builder-fallback-skips`
- `--builder-fallback-skips-per-epoch`
- `--builder-fallback-epochs-since-finalization`
- `--builder-fallback-disable-checks`

[mev-rs]: https://github.com/ralexstokes/mev-rs
[mev-boost]: https://github.com/flashbots/mev-boost

## Per-validator configuration

Refer to [fee recipient documentation](suggested-fee-recipient)

//TODO(sean): add docs about the strict fee recipient flag

## Gas Limit


# Merge Migration

This document provides detail for users who have been running a Lighthouse node *before* the merge
and are now preparing their node for the merge transition.

## "Pre-Merge" and "Post-Merge"

As of [v2.4.0](https://github.com/sigp/lighthouse/releases/tag/v2.4.0) Lighthouse can be considered
to have two modes:

- "Pre-merge": `--execution-endpoint` flag *is not* provided.
- "Post-merge": `--execution-endpoint` flag *is* provided.

A "pre-merge" node, by definition, will fail to transition through the merge. Such a node *must* be
upgraded before the Bellatrix upgrade.

## Migration

Let us look at an example of the command line arguments for a pre-merge production staking BN:

```bash
lighthouse \
    --network mainnet \
    beacon_node \
    --http \
    --eth1-endpoints http://localhost:8545,https://TOKEN@eth2-beacon-mainnet.infura.io
```

Converting the above to a post-merge configuration would render:

```bash
lighthouse \
    --network mainnet \
    beacon_node \
    --http \
    --execution-endpoint http://localhost:8551
    --execution-jwt ~/.ethereum/geth/jwtsecret
```

The changes here are:

1. Remove `--eth1-endpoints`
    - The endpoint at `localhost` can be retained, it is our local execution engine. Once it is
      upgraded to a merge-compatible release it will be used in the post-merge environment.
    - The `infura.io` endpoint will be abandoned, Infura and most other third-party node providers
      *are not* compatible with post-merge BNs.
2. Add the `--execution-endpoint` flag.
    - We have reused the node at `localhost`, however we've switched to the authenticated engine API
      port `8551`. All execution engines will have a specific port for this API, however it might
      not be `8551`, see their documentation for details.
3. Add the `--execution-jwt` flag.
    - This is the path to a file containing a 32-byte secret for authenticating the BN with the
      execution engine. In this example our execution engine is Geth, so we've chosen the default
      location for Geth. Your execution engine might have a different path. It is critical that both
      the BN and execution engine reference a file with the same value, otherwise they'll fail to
      communicate.

Note that the `--network` and `--http` flags haven't changed. The only changes required for the
merge are ensuring that `--execution-endpoint` and `--execution-jwt` flags are provided! In fact,
you can even leave the `--eth1-endpoints` flag there, it will be ignored. This is not recommended as
a deprecation warning will be logged and Lighthouse *may* remove these flags in the future.

There are no changes required for the validator client, apart from ensure it has been updated to the
same version as the beacon node. Check the version with `lighthouse --version`.

## The relationship between `--eth1-endpoints` and `--execution-endpoint`

Pre-merge users will be familiar with the `--eth1-endpoints` flag. This provides a list of Ethereum
"eth1" nodes (e.g., Geth, Nethermind, etc). Each beacon node (BN) can have multiple eth1 endpoints
and each eth1 endpoint can have many BNs connection (many-to-many relationship). The eth1 node
provides a source of truth for the [deposit
contract](https://ethereum.org/en/staking/deposit-contract/) and beacon chain proposers include this
information in beacon blocks in order to on-board new validators. BNs exclusively use the `eth`
namespace on the eth1 [JSON-RPC API](https://ethereum.org/en/developers/docs/apis/json-rpc/) to
achieve this.

To progress through the Bellatrix upgrade nodes will need a *new* connection to an "eth1" node;
`--execution-endpoint`. This connection has a few different properties. Firstly, the term "eth1
node" has been deprecated and replaced with "execution engine". Whilst "eth1 node" and "execution
engine" still refer to the same projects (Geth, Nethermind, etc) the former refers to the pre-merge
versions and the latter refers to post-merge versions. Secondly, there is a strict one-to-one
relationship between Lighthouse and the execution engine; only one Lighthouse node can connect to
one execution engine. Thirdly, it is impossible to fully verify the post-merge chain without an
execution engine. It *was* possible to verify the pre-merge chain without an eth1 node, it was just
impossible to reliably *propose* blocks without it.

Since an execution engine is a hard requirement in the post-merge chain and the execution engine
contains the transaction history of the Ethereum chain, there is no longer a need for the
`--eth1-endpoints` flag for information about the deposit contract. The `--execution-endpoint` can
be used for all such queries. Therefore we can say that where `--execution-endpoint` is included
`--eth1-endpoints` should be omitted.

## What about multiple execution endpoints?

Since an execution engine can only have one connected BN, the value of having multiple execution
engines connected to the same BN is very low. An execution engine cannot be shared between BNs to
reduce costs.

Whilst having multiple execution engines connected to a single BN might be useful for advanced
testing scenarios, Lighthouse (and other consensus clients) have decided to support *only one*
execution endpoint. Such scenarios could be resolved with a custom-made HTTP proxy.

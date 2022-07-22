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
versions and the later refers to post-merge versions. Secondly, there is a strict one-to-one
relationship between Lighthouse and the execution engine; only one Lighthouse node can connect to
one execution engine. Thirdly, it's impossible to fully verify the post-merge chain without an
execution engine. It *was* possible to verify the pre-merge chain without an eth1 node, it was just
impossible to reliably *propose* blocks without it.

Since an execution engine is a hard requirement in the post-merge chain and the execution engine
contains the transaction history of the Ethereum chain, there is no longer a need for the
`--eth1-endpoints` flag for information about the deposit contract. The `--execution-endpoint` can
be used for all such queries. Therefore we can say that where `--execution-endpoint` is included
`--eth1-endpoints` should be omitted.

## Migrating CLI arguments



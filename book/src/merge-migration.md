# Merge Migration

This document provides detail for users who want to run a merge-ready Lighthouse node.

> The merge is occurring on mainnet in September. You _must_ have a merge-ready setup by September 6
> 2022.

## Necessary Configuration

There are two configuration changes required for a Lighthouse node to operate correctly throughout
the merge:

1. You *must* run your own execution engine such as Geth or Nethermind alongside Lighthouse.
   You *must* update your `lighthouse bn` configuration to connect to the execution engine using new
   flags which are documented on this page in the
   [Connecting to an execution engine](#connecting-to-an-execution-engine) section.
2. If your Lighthouse node has validators attached you *must* nominate an Ethereum address to
   receive transactions tips from blocks proposed by your validators. These changes should
   be made to your `lighthouse vc` configuration, and are covered on the
   [Suggested fee recipient](./suggested-fee-recipient.md) page.

Additionally, you _must_ update Lighthouse to v3.0.0 (or later), and must update your execution
engine to a merge-ready version.

## When?

You must configure your node to be merge-ready before the Bellatrix fork occurs on the network
on which your node is operating.

* **Mainnet**: the Bellatrix fork is scheduled for epoch 144896, September 6 2022 11:34 UTC.
  You must ensure your node configuration is updated before then in order to continue following
  the chain. We recommend updating your configuration now.

* **Goerli (Prater)**, **Ropsten**, **Sepolia**, **Kiln**: the Bellatrix fork has already occurred.
  You must have a merge-ready configuration right now.

## Connecting to an execution engine

The Lighthouse beacon node must connect to an execution engine in order to validate the transactions
present in post-merge blocks. Two new flags are used to configure this connection:

- `--execution-endpoint <URL>`: the URL of the execution engine API. Often this will be
  `http://localhost:8551`.
- `--execution-jwt <FILE>`: the path to the file containing the JWT secret shared by Lighthouse and the
  execution engine.

If you set up an execution engine with `--execution-endpoint` then you *must* provide a JWT secret
using `--execution-jwt`. This is a mandatory form of authentication that ensures that Lighthouse
has authority to control the execution engine.

> Tip: the --execution-jwt-secret-key <STRING> flag can be used instead of --execution-jwt <FILE>.
> This is useful, for example, for users who wish to inject the value into a Docker container without
> needing to pass a jwt secret file.

The execution engine connection must be **exclusive**, i.e. you must have one execution node
per beacon node. The reason for this is that the beacon node _controls_ the execution node. Please
see the [FAQ](#faq) for further information about why many:1 and 1:many configurations are not
supported.

### Execution engine configuration

Each execution engine has its own flags for configuring the engine API and JWT. Please consult
the relevant page for your execution engine for the required flags:

- [Geth: Connecting to Consensus Clients](https://geth.ethereum.org/docs/interface/consensus-clients)
- [Nethermind: Running Nethermind Post Merge](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge)
- [Besu: Prepare For The Merge](https://besu.hyperledger.org/en/stable/HowTo/Upgrade/Prepare-for-The-Merge/)

Once you have configured your execution engine to open up the engine API (usually on port 8551) you
should add the URL to your `lighthouse bn` flags with `--execution-endpoint <URL>`, as well as
the path to the JWT secret with `--execution-jwt <FILE>`.

There are merge-ready releases of all compatible execution engines available now.

### Example

Let us look at an example of the command line arguments for a pre-merge production staking BN:

```bash
lighthouse \
    --network mainnet \
    beacon_node \
    --http \
    --eth1-endpoints http://localhost:8545,https://mainnet.infura.io/v3/TOKEN
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

### The relationship between `--eth1-endpoints` and `--execution-endpoint`

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

## FAQ

### How do I know if my node is set up correctly?

Lighthouse will log a message indicating that it is ready for the merge:

```
INFO Ready for the merge, current_difficulty: 10789363, terminal_total_difficulty: 10790000
```

Once the merge has occurred you should see that Lighthouse remains in sync and marks blocks
as `verified` indicating that they have been processed successfully by the execution engine:

```
INFO Synced, slot: 3690668, block: 0x1244…cb92, epoch: 115333, finalized_epoch: 115331, finalized_root: 0x0764…2a3d, exec_hash: 0x929c…1ff6 (verified), peers: 78
```

### Can I still use the `--staking` flag?

Yes. The `--staking` flag is just an alias for `--http --eth1`. The `--eth1` flag is now superfluous
so `--staking` is equivalent to `--http`. You need either `--staking` or `--http` for the validator
client to be able to connect to the beacon node.

### Can I use `http://localhost:8545` for the execution endpoint?

Most execution nodes use port `8545` for the Ethereum JSON-RPC API. Unless custom configuration is
used, an execution node _will not_ provide the necessary engine API on port `8545`. You should
not attempt to use `http://localhost:8545` as your engine URL and should instead use
`http://localhost:8551`.

### Can I share an execution node between multiple beacon nodes (many:1)?

It is **not** possible to connect more than one beacon node to the same execution engine. There must be a 1:1 relationship between beacon nodes and execution nodes.

The beacon node controls the execution node via the engine API, telling it which block is the
current head of the chain. If multiple beacon nodes were to connect to a single execution node they
could set conflicting head blocks, leading to frequent re-orgs on the execution node.

We imagine that in future there will be HTTP proxies available which allow users to nominate a
single controlling beacon node, while allowing consistent updates from other beacon nodes.

### What about multiple execution endpoints (1:many)?

It is **not** possible to connect one beacon node to more than one execution engine. There must be a 1:1 relationship between beacon nodes and execution nodes.

Since an execution engine can only have one controlling BN, the value of having multiple execution
engines connected to the same BN is very low. An execution engine cannot be shared between BNs to
reduce costs.

Whilst having multiple execution engines connected to a single BN might be useful for advanced
testing scenarios, Lighthouse (and other consensus clients) have decided to support *only one*
execution endpoint. Such scenarios could be resolved with a custom-made HTTP proxy.

## Additional Resources

There are several community-maintained guides which provide more background information, as well as
guidance for specific setups.

- [Ethereum.org: The Merge](https://ethereum.org/en/upgrades/merge/)
- [Ethereum Staking Launchpad: Merge Readiness](https://launchpad.ethereum.org/en/merge-readiness).
- [CoinCashew: Ethereum Merge Upgrade Checklist](https://www.coincashew.com/coins/overview-eth/ethereum-merge-upgrade-checklist-for-home-stakers-and-validators)
- [EthDocker: Merge Preparation](https://eth-docker.net/docs/About/MergePrep/)
- [Remy Roy: How to join the Goerli/Prater merge testnet](https://github.com/remyroy/ethstaker/blob/main/merge-goerli-prater.md)

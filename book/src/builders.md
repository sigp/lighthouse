# MEV and Lighthouse

Lighthouse is able to interact with servers that implement the [builder
API](https://github.com/ethereum/builder-specs), allowing it to produce blocks without having
knowledge of the transactions included in the block. This enables Lighthouse to outsource the job of
transaction gathering/ordering within a block to parties specialized in this particular task. For
economic reasons, these parties will refuse to reveal the list of transactions to the validator
before the validator has committed to (i.e. signed) the block. A primer on MEV can be found
[here](https://ethereum.org/en/developers/docs/mev).

Using the builder API is not known to introduce additional slashing risks, however a live-ness risk
(i.e. the ability for the chain to produce valid blocks) is introduced because your node will be
signing blocks without executing the transactions within the block. Therefore, it won't know whether
the transactions are valid, and it may sign a block that the network will reject. This would lead to
a missed proposal and the opportunity cost of lost block rewards.

## How to connect to a builder

The beacon node and validator client each require a new flag for lighthouse to be fully compatible with builder API servers.

```
lighthouse bn --builder https://mainnet-builder.test
```
The `--builder` flag will cause the beacon node to query the provided URL during block production for a block
payload with stubbed-out transactions. If this request fails, Lighthouse will fall back to the local
execution engine and produce a block using transactions gathered and verified locally.

The beacon node will *only* query for this type of block (a "blinded" block) when a validator specifically requests it.
Otherwise, it will continue to serve full blocks as normal. In order to configure the validator client to query for
blinded blocks, you should use the following flag:

```
lighthouse vc --builder-proposals
```
With the `--builder-proposals` flag, the validator client will ask for blinded blocks for all validators it manages.
In order to configure whether a validator queries for blinded blocks check out [this section.](#validator-client-configuration)

## Multiple builders

Lighthouse currently only supports a connection to a single builder. If you'd like to connect to multiple builders or
relays, run one of the following services and configure lighthouse to use it with the `--builder` flag.

* [`mev-boost`][mev-boost]
* [`mev-rs`][mev-rs]

## Validator Client Configuration

In the validator client you can configure gas limit and fee recipient on a per-validator basis. If no gas limit is 
configured, Lighthouse will use a default gas limit of 30,000,000, which is the current default value used in execution 
engines.  You can also enable or disable use of external builders on a per-validator basis rather than using 
`--builder-proposals`, which enables external builders for all validators. In order to manage these configurations
per-validator, you can either make updates to the `validator_definitions.yml` file or you can use the HTTP requests
described below.

Both the gas limit and fee recipient will be passed along as suggestions to connected builders. If there is a discrepancy
in either, it will *not* keep you from proposing a block with the builder. This is because the bounds on gas limit are
calculated based on prior execution blocks, so an honest external builder will make sure that even if your 
requested gas limit value is out of the specified range, a valid gas limit in the direction of your request will be 
used in constructing the block. Depending on the connected relay, payment to the proposer might be in the form of a
transaction within the block to the fee recipient, so a discrepancy in fee recipient might not indicate that there 
is something afoot. 

> Note: The gas limit configured here is effectively a vote on block size, so the configuration should not be taken lightly. 
> 30,000,000 is currently seen as a value balancing block size with how expensive it is for
> the network to validate blocks. So if you don't feel comfortable making an informed "vote", using the default value is 
> encouraged. We will update the default value if the community reaches a rough consensus on a new value.

### Set Gas Limit via HTTP

To update gas limit per-validator you can use the [standard key manager API][gas-limit-api].

Alternatively, you can use the [lighthouse API](api-vc-endpoints.md). See below for an example.

### Enable/Disable builder proposals via HTTP

Use the [lighthouse API](api-vc-endpoints.md) to enable/disable use of the builder API on a per-validator basis.
You can also update the configured gas limit with these requests.

#### `PATCH /lighthouse/validators/:voting_pubkey`


#### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/:voting_pubkey`    |
| Method            | PATCH                                      |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200, 400                                   |

#### Example Path

```
localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde
```

#### Example Request Body
Each field is optional.
```json
{
    "builder_proposals": true,
    "gas_limit": 30000001
}
```

#### Example Response Body

```json
null
```
### Fee Recipient

Refer to [suggested fee recipient](suggested-fee-recipient.md) documentation.

### Validator definitions example

You can also directly configure these fields in the `validator_definitions.yml` file.

```
---
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
  suggested_fee_recipient: "0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21"
  gas_limit: 30000001
  builder_proposals: true
- enabled: false
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore voting_keystore_path: /home/paul/.lighthouse/validators/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477/voting-keystore.json
  voting_keystore_password: myStrongpa55word123&$
  suggested_fee_recipient: "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
  gas_limit: 33333333
  builder_proposals: true
```

## Circuit breaker conditions

By outsourcing payload construction and signing blocks without verifying transactions, we are creating a new risk to
live-ness. If most of the network is using a small set of relays and one is bugged, a string of missed proposals could
happen quickly. This is not only generally bad for the network, but if you have a proposal coming up, you might not
realize that your next proposal is likely to be missed until it's too late. So we've implemented some "chain health"
checks to try and avoid scenarios like this.

By default, Lighthouse is strict with these conditions, but we encourage users to learn about and adjust them.

- `--builder-fallback-skips`  - If we've seen this number of skip slots on the canonical chain in a row prior to proposing, we will NOT query
 any connected builders, and will use the local execution engine for payload construction.
- `--builder-fallback-skips-per-epoch` - If we've seen this number of skip slots on the canonical chain in the past `SLOTS_PER_EPOCH`, we will NOT
 query any connected builders, and will use the local execution engine for payload construction.
- `--builder-fallback-epochs-since-finalization` - If we're proposing and the chain has not finalized within
  this number of epochs, we will NOT query any connected builders, and will use the local execution engine for payload
  construction. Setting this value to anything less than 2 will cause the node to NEVER query connected builders. Setting
  it to 2 will cause this condition to be hit if there are skips slots at the start of an epoch, right before this node
  is set to propose.
- `--builder-fallback-disable-checks` - This flag disables all checks related to chain health. This means the builder
  API will always be used for payload construction, regardless of recent chain conditions.

## Builder Profit Threshold 

If you are generally uneasy with the risks associated with outsourced payload production (liveness/censorship) but would
consider using it for the chance of out-sized rewards, this flag may be useful:

`--builder-profit-threshold <WEI_VALUE>`

The number provided indicates the minimum reward that an external payload must provide the proposer for it to be considered 
for inclusion in a proposal. For example, if you'd only like to use an external payload for a reward of >= 0.25 ETH, you
would provide your beacon node with `--builder-profit-threshold 250000000000000000`. If it's your turn to propose and the 
most valuable payload offered by builders is only 0.1 ETH, the local execution engine's payload will be used. Currently,
this threshold just looks at the value of the external payload. No comparison to the local payload is made, although 
this feature will likely be added in the future.

[mev-rs]: https://github.com/ralexstokes/mev-rs
[mev-boost]: https://github.com/flashbots/mev-boost
[gas-limit-api]: https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit

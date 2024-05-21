# Maximal Extractable Value (MEV)

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

```bash
lighthouse bn --builder https://mainnet-builder.test
```

The `--builder` flag will cause the beacon node to simultaneously query the provided URL and the local execution engine during block production for a block payload with stubbed-out transactions. If either fails, the successful result will be used; If both succeed, the more profitable result will be used.

The beacon node will *only* query for this type of block (a "blinded" block) when a validator specifically requests it.
Otherwise, it will continue to serve full blocks as normal. In order to configure the validator client to query for
blinded blocks, you should use the following flag:

```bash
lighthouse vc --builder-proposals
```

With the `--builder-proposals` flag, the validator client will ask for blinded blocks for all validators it manages.

```bash
lighthouse vc --prefer-builder-proposals
```

With the `--prefer-builder-proposals` flag, the validator client will always prefer blinded blocks, regardless of the payload value, for all validators it manages.

```bash
lighthouse vc --builder-boost-factor <INTEGER>
```

With the `--builder-boost-factor` flag, a percentage multiplier is applied to the builder's payload value when choosing between a
builder payload header and payload from the paired execution node. For example, `--builder-boost-factor 50` will only use the builder payload if it is 2x more profitable than the local payload.

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
`--builder-proposals`, `--builder-boost-factor` or `--prefer-builder-proposals`, which apply builder related preferences for all validators.
In order to manage these configurations per-validator, you can either make updates to the `validator_definitions.yml` file
or you can use the HTTP requests described below.

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

```text
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

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X PATCH "http://localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde" \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d '{
    "builder_proposals": true,
    "gas_limit": 30000001
}' | jq
```

If you are having permission issue with accessing the API token file, you can modify the header to become `-H "Authorization: Bearer $(sudo cat ${DATADIR}/validators/api-token.txt)"`

#### Example Response Body

```json
null
```

A `null` response indicates that the request is successful. At the same time, `lighthouse vc` will show a log which looks like:

```text
INFO Published validator registrations to the builder network, count: 3, service: preparation
```

### Fee Recipient

Refer to [suggested fee recipient](suggested-fee-recipient.md) documentation.

### Validator definitions example

You can also directly configure these fields in the `validator_definitions.yml` file.

```text
---
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
  suggested_fee_recipient: "0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21"
  gas_limit: 30000001
  builder_proposals: true
  builder_boost_factor: 50
- enabled: false
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore voting_keystore_path: /home/paul/.lighthouse/validators/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477/voting-keystore.json
  voting_keystore_password: myStrongpa55word123&$
  suggested_fee_recipient: "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
  gas_limit: 33333333
  builder_proposals: true
  prefer_builder_proposals: true
```

## Circuit breaker conditions

By outsourcing payload construction and signing blocks without verifying transactions, we are creating a new risk to
live-ness. If most of the network is using a small set of relays and one is bugged, a string of missed proposals could
happen quickly. This is not only generally bad for the network, but if you have a proposal coming up, you might not
realize that your next proposal is likely to be missed until it's too late. So we've implemented some "chain health"
checks to try and avoid scenarios like this.

By default, Lighthouse is strict with these conditions, but we encourage users to learn about and adjust them.

* `--builder-fallback-skips`  - If we've seen this number of skip slots on the canonical chain in a row prior to proposing, we will NOT query
 any connected builders, and will use the local execution engine for payload construction.
* `--builder-fallback-skips-per-epoch` - If we've seen this number of skip slots on the canonical chain in the past `SLOTS_PER_EPOCH`, we will NOT
 query any connected builders, and will use the local execution engine for payload construction.
* `--builder-fallback-epochs-since-finalization` - If we're proposing and the chain has not finalized within
  this number of epochs, we will NOT query any connected builders, and will use the local execution engine for payload
  construction. Setting this value to anything less than 2 will cause the node to NEVER query connected builders. Setting
  it to 2 will cause this condition to be hit if there are skips slots at the start of an epoch, right before this node
  is set to propose.
* `--builder-fallback-disable-checks` - This flag disables all checks related to chain health. This means the builder
  API will always be used for payload construction, regardless of recent chain conditions.

## Checking your builder config

You can check that your builder is configured correctly by looking for these log messages.

On start-up, the beacon node will log if a builder is configured:

```text
INFO Using external block builder
```

At regular intervals the validator client will log that it successfully registered its validators
with the builder network:

```text
INFO Published validator registrations to the builder network
```

When you successfully propose a block using a builder, you will see this log on the beacon node:

```text
INFO Successfully published a block to the builder network
```

If you don't see that message around the time of your proposals, check your beacon node logs
for `INFO` and `WARN` messages indicating why the builder was not used.

Examples of messages indicating fallback to a locally produced block are:

```text
INFO Builder did not return a payload
```

```text
WARN Builder error when requesting payload
```

```text
WARN Builder returned invalid payload
```

```text
INFO Builder payload ignored
```

```text
INFO Chain is unhealthy, using local payload
```

In case of fallback you should see a log indicating that the locally produced payload was
used in place of one from the builder:

```text
INFO Reconstructing a full block using a local payload
```

## Information for block builders and relays

Block builders and relays can query beacon node events from the [Events API](https://ethereum.github.io/beacon-APIs/#/Events/eventstream). An example of querying the payload attributes in the Events API is outlined in [Beacon node API - Events API](./api-bn.md#events-api)

[mev-rs]: https://github.com/ralexstokes/mev-rs
[mev-boost]: https://github.com/flashbots/mev-boost
[gas-limit-api]: https://ethereum.github.io/keymanager-APIs/#/Gas%20Limit

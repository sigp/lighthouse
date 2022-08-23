# Suggested Fee Recipient

The _fee recipient_ is an Ethereum address nominated by a beacon chain validator to receive
tips from user transactions. If you run validators on a network that has already merged
or is due to merge soon then you should nominate a fee recipient for your validators.

## Background

During post-merge block production, the Beacon Node (BN) will provide a `suggested_fee_recipient` to
the execution node. This is a 20-byte Ethereum address which the EL might choose to set as the
coinbase and the recipient of other fees or rewards.

There is no guarantee that an execution node will use the `suggested_fee_recipient` to collect fees,
it may use any address it chooses. It is assumed that an honest execution node *will* use the
`suggested_fee_recipient`, but users should note this trust assumption. Check out the
[strict fee recipient](#strict-fee-recipient) section for how to mitigate this assumption.

The `suggested_fee_recipient` can be provided to the VC, which will transmit it to the BN. The BN also
has a choice regarding the fee recipient it passes to the execution node, creating another
noteworthy trust assumption.

To be sure *you* control your fee recipient value, run your own BN and execution node (don't use
third-party services).

## How to configure a suggested fee recipient

The Lighthouse VC provides two methods for setting the `suggested_fee_recipient` (also known
simply as the "fee recipient") to be passed to the execution layer during block production. The
Lighthouse BN also provides a method for defining this value, should the VC not transmit a value.

Assuming trustworthy nodes, the priority for the three methods is:

1. `validator_definitions.yml`
1. `--suggested-fee-recipient` provided to the VC.
1. `--suggested-fee-recipient` provided to the BN.

> **NOTE**: It is **not** recommended to _only_ set the fee recipient on the beacon node, as this results
> in sub-optimal block proposals. See [this issue](https://github.com/sigp/lighthouse/issues/3432)
> for details.

### 1. Setting the fee recipient in the `validator_definitions.yml`

Users can set the fee recipient in `validator_definitions.yml` with the `suggested_fee_recipient`
key. This option is recommended for most users, where each validator has a fixed fee recipient.

Below is an example of the validator_definitions.yml with `suggested_fee_recipient` values:

```
---
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
  suggested_fee_recipient: "0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21"
- enabled: false
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore voting_keystore_path: /home/paul/.lighthouse/validators/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477/voting-keystore.json
  voting_keystore_password: myStrongpa55word123&$
  suggested_fee_recipient: "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
```

### 2. Using the "--suggested-fee-recipient" flag on the validator client

The `--suggested-fee-recipient` can be provided to the VC to act as a default value for all
validators where a `suggested_fee_recipient` is not loaded from another method.

### 3. Using the "--suggested-fee-recipient" flag on the beacon node

The `--suggested-fee-recipient` can be provided to the BN to act as a default value when the
validator client does not transmit a `suggested_fee_recipient` to the BN.

**This value should be considered an emergency fallback**. You should set the fee recipient in the
validator client in order for the execution node to be given adequate notice of block proposal.

## Setting the fee recipient dynamically using the keymanager API

When the [validator client API](api-vc.md) is enabled, the
[standard keymanager API](https://ethereum.github.io/keymanager-APIs/) includes an endpoint
for setting the fee recipient dynamically for a given public key. When used, the fee recipient
will be saved in `validator_definitions.yml` so that it persists across restarts of the validator
client.

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/eth/v1/validator/{pubkey}/feerecipient`  |
| Method            | POST                                       |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 202, 404                                   |

#### Example Request Body
```json
{
    "ethaddress": "0x1D4E51167DBDC4789a014357f4029ff76381b16c"
}
```

```bash
DATADIR=$HOME/.lighthouse/mainnet
PUBKEY=0xa9735061c84fc0003657e5bd38160762b7ef2d67d280e00347b1781570088c32c06f15418c144949f5d736b1d3a6c591
FEE_RECIPIENT=0x1D4E51167DBDC4789a014357f4029ff76381b16c

curl -X POST \
    -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
    -H "Content-Type: application/json" \
    -d "{ \"ethaddress\": \"${FEE_RECIPIENT}\" }" \
    http://localhost:5062/eth/v1/validator/${PUBKEY}/feerecipient | jq
```

#### Successful Response (202)
```json
null
```

### Querying the fee recipient

The same path with a `GET` request can be used to query the fee recipient for a given public key at any time.

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/eth/v1/validator/{pubkey}/feerecipient`  |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200, 404                                   |

```bash
DATADIR=$HOME/.lighthouse/mainnet
PUBKEY=0xa9735061c84fc0003657e5bd38160762b7ef2d67d280e00347b1781570088c32c06f15418c144949f5d736b1d3a6c591

curl -X GET \
    -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
    -H "Content-Type: application/json" \
    http://localhost:5062/eth/v1/validator/${PUBKEY}/feerecipient | jq
```

#### Successful Response (200)
```json
{
  "data": {
    "pubkey": "0xa9735061c84fc0003657e5bd38160762b7ef2d67d280e00347b1781570088c32c06f15418c144949f5d736b1d3a6c591",
    "ethaddress": "0x1d4e51167dbdc4789a014357f4029ff76381b16c"
  }
}
```

### Removing the fee recipient

The same path with a `DELETE` request can be used to remove the fee recipient for a given public key at any time.
This is useful if you want the fee recipient to fall back to the validator client (or beacon node) default.

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/eth/v1/validator/{pubkey}/feerecipient`  |
| Method            | DELETE                                     |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 204, 404                                   |

```bash
DATADIR=$HOME/.lighthouse/mainnet
PUBKEY=0xa9735061c84fc0003657e5bd38160762b7ef2d67d280e00347b1781570088c32c06f15418c144949f5d736b1d3a6c591

curl -X DELETE \
    -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
    -H "Content-Type: application/json" \
    http://localhost:5062/eth/v1/validator/${PUBKEY}/feerecipient | jq
```

#### Successful Response (204)
```json
null
```

## Strict Fee Recipient

If the flag `--strict-fee-recipient` is set in the validator client, Lighthouse will refuse to sign any block whose
`fee_recipient` does not match the `suggested_fee_recipient` sent by this validator. This applies to both the normal
block proposal flow and block proposals through the builder API. Proposals through the builder API are more likely
to have a discrepancy in `fee_recipient` so you should be aware of how your connected relay sends proposer payments before
using this flag. If this flag is used, a fee recipient mismatch in the builder API flow will result in a fallback to the
local execution engine for payload construction, where a strict fee recipient check will still be applied.

## FAQ

### Why do I have to nominate an Ethereum address as the fee recipient?

You might wonder why the validator can't just accumulate transactions fees in the same way that it
accumulates other staking rewards. The reason for this is that transaction fees are computed and
validated by the execution node, and therefore need to be paid to an address that exists on the
execution chain. Validators use BLS keys which do not correspond to Ethereum addresses, so they
have no "presence" on the execution chain. Therefore it's necessary for each validator to nominate
a separate fee recipient address.

# Validator Graffiti

Lighthouse provides four options for setting validator graffiti.

## 1. Using the "--graffiti-file" flag on the validator client

Users can specify a file with the `--graffiti-file` flag. This option is useful for dynamically changing graffitis for various use cases (e.g. drawing on the beaconcha.in graffiti wall). This file is loaded once on startup and reloaded every time a validator is chosen to propose a block.

Usage:
`lighthouse vc --graffiti-file graffiti_file.txt`

The file should contain key value pairs corresponding to validator public keys and their associated graffiti. The file can also contain a `default` key for the default case.

```text
default: default_graffiti
public_key1: graffiti1
public_key2: graffiti2
...
```

Below is an example of a graffiti file:

```text
default: Lighthouse
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: mr f was here
0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477: mr v was here
```

Lighthouse will first search for the graffiti corresponding to the public key of the proposing validator, if there are no matches for the public key, then it uses the graffiti corresponding to the default key if present.

## 2. Setting the graffiti in the `validator_definitions.yml`

Users can set validator specific graffitis in `validator_definitions.yml` with the `graffiti` key. This option is recommended for static setups where the graffitis won't change on every new block proposal.

You can also update the graffitis in the `validator_definitions.yml` file using the [Lighthouse API](api_vc_endpoints.html#patch-lighthousevalidatorsvoting_pubkey). See example in [Set Graffiti via HTTP](#set-graffiti-via-http).

Below is an example of the validator_definitions.yml with validator specific graffitis:

```text
---
- enabled: true
  voting_public_key: "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007/voting-keystore.json
  voting_keystore_password_path: /home/paul/.lighthouse/secrets/0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007
  graffiti: "mr f was here"
- enabled: false
  voting_public_key: "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477"
  type: local_keystore
  voting_keystore_path: /home/paul/.lighthouse/validators/0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477/voting-keystore.json
  voting_keystore_password: myStrongpa55word123&$
  graffiti: "somethingprofound"
```

## 3. Using the "--graffiti" flag on the validator client

Users can specify a common graffiti for all their validators using the `--graffiti` flag on the validator client.

Usage: `lighthouse vc --graffiti example`

## 4. Using the "--graffiti" flag on the beacon node

Users can also specify a common graffiti using the `--graffiti` flag on the beacon node as a common graffiti for all validators.

Usage: `lighthouse bn --graffiti fortytwo`

> Note: The order of preference for loading the graffiti is as follows:
>
> 1. Read from `--graffiti-file` if provided.
> 1. If `--graffiti-file` is not provided or errors, read graffiti from `validator_definitions.yml`.
> 1. If graffiti is not specified in `validator_definitions.yml`, load the graffiti passed in the `--graffiti` flag on the validator client.
> 1. If the `--graffiti` flag on the validator client is not passed, load the graffiti passed in the `--graffiti` flag on the beacon node.
> 1. If the `--graffiti` flag is not passed, load the default Lighthouse graffiti.

## Set Graffiti via HTTP

Use the [Lighthouse API](api_vc_endpoints.md) to set graffiti on a per-validator basis. This method updates the graffiti
both in memory and in the `validator_definitions.yml` file. The new graffiti will be used in the next block proposal
without requiring a validator client restart.

Refer to [Lighthouse API](api_vc_endpoints.html#patch-lighthousevalidatorsvoting_pubkey) for API specification.

### Example Command

```bash
DATADIR=/var/lib/lighthouse
curl -X PATCH "http://localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde" \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d '{
    "graffiti": "Mr F was here"
}' | jq
```

A `null` response indicates that the request is successful.

## Automatically append client version info to user graffiti

> Note: this feature only works when a Lighthouse validator client is connected to a Lighthouse beacon node.

In the interest of obtaining client diversity data, Lighthouse will by default automatically append client version info
to user graffiti in proposed blocks.

For example, you set the graffiti in the validator client as `This is my graffiti`. You are using Lighthouse (`LH`) v8.1.3
with commit hash `176cce5` and Reth (`RH`) v2.2.0 with commit hash `88505c7`. The appended graffiti will include:

- Execution layer client code
- First two bytes of the execution layer commit hash
- Consensus layer client code
- First two bytes of the consensus layer commit hash

When the user graffiti is less than 20 characters, as in the above example, the appended graffiti when proposing a block
will be: `This is my graffiti RH8850LH176c`.

Given that the total size of the graffiti is 32 bytes, if the appended graffiti exceeds the size, the appended
client version info will automatically be shortened. Some examples are as follows, where the last part of the graffiti is the
appended client version info.

When the user graffiti is between 20-23 characters:
`This is my graffiti yo RH88LH17`

When the user graffiti is between 24-27 characters:
`This is my graffiti string RHLH`

When the user graffiti is between 28-29 characters:
`This is my graffiti string yo RH`

When the user graffiti is between 30-32 characters, no client version info will be appended:
`This is my graffiti string yo yo`

To opt out from this, when using a Lighthouse beacon node, use the flag `--graffiti-append false` on the validator client.  This will retain your own graffiti when proposing a block, without appending any client version info.

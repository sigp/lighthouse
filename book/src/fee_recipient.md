# Fee Recipient

Lighthouse provides two options for setting the `suggested_fee_recipient` (also known simply as the
"fee recipient") to be passed to the execution layer during block production. This value is only
relevant to nodes running validators.

Users may configure the fee recipient via `validator_definitions.yml` or via the
`--fee-recipient-file` flag. The value in `validator_definitions.yml` will always take precedence.

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

### 2. Using the "--fee-recipient-file" flag on the validator client

Users can specify a file with the `--fee-recipient-file` flag. This option is useful for dynamically
changing fee recipients. This file is reloaded each time a validator is chosen to propose a block.

Usage:
`lighthouse vc --fee-recipient-file fee_recipient.txt`

The file should contain key value pairs corresponding to validator public keys and their associated
fee recipient. The file can optionally contain a `default` key for the default case.

```
default: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477: 0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d
```

Lighthouse will first search for the fee recipient corresponding to the public key of the proposing
validator, if there are no matches for the public key, then it uses the address corresponding to the
default key (if present).

# Validator graffiti

Lighthouse provides 3 options for setting validator graffitis on the validator client.

## Using the `--graffiti-file` flag on the validator client
Users can specify a file with the `--graffiti-file` flag. This option is useful for dynamically changing graffitis for various use cases (e.g. drawing on the beaconcha.in graffiti wall). This file is loaded once on startup and reloaded everytime a validator is chosen to propose a block.

Usage:
`lighthouse vc --graffiti-file graffiti_file.txt`

The file should contain a key value pair corresponding to validator public key and the corresponding graffiti.
```
default: default_graffiti
public_key1: graffiti1
public_key2: graffiti2
...
```

Below is an example of a graffiti file:

```
default: Lighthouse
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: mr f was here
0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477: mr v was here
```

Lighthouse will first search for the graffiti corresponding to the public key of the proposing validator, if there are no matches for the public key, then it uses the graffiti corresponding to the default key.

## Setting the graffiti in the `validator_definitions.yml`
Users can set validator specific graffitis in `validator_definitions.yml` with the graffiti key. This is useful for static setups where the graffitis won't change on every new block proposal.

Below is an example of the validator_definitions.yml with validator specific graffitis:
```
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

## Using the `--graffiti` flag on the validator client
Users can specify a common graffiti for all their validators using the `--graffiti` flag.

Usage: `lighthouse vc --graffiti fortytwo`

The order of preference for loading the graffiti is as follows:
1. Read from `--graffiti-file` if provided.
2. If `--graffiti-file` is not provided or errors, read graffiti from `validator_definitions.yml`.
3. If graffiti is not specified in `validator_definitions.yml`, load the graffiti passed in the `--graffiti` flag.
4. If the `--graffiti` flag is not passed, load the default Lighthouse graffiti.
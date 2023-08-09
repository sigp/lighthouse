# Validator Client API: Endpoints

## Endpoints

HTTP Path | Description |
| --- | -- |
[`GET /lighthouse/version`](#get-lighthouseversion) | Get the Lighthouse software version.
[`GET /lighthouse/health`](#get-lighthousehealth) | Get information about the host machine.
[`GET /lighthouse/ui/health`](#get-lighthouseuihealth) | Get information about the host machine. Focused for UI applications.
[`GET /lighthouse/spec`](#get-lighthousespec) | Get the Ethereum proof-of-stake consensus specification used by the validator.
[`GET /lighthouse/auth`](#get-lighthouseauth) | Get the location of the authorization token.
[`GET /lighthouse/validators`](#get-lighthousevalidators) | List all validators.
[`GET /lighthouse/validators/:voting_pubkey`](#get-lighthousevalidatorsvoting_pubkey) | Get a specific validator.
[`PATCH /lighthouse/validators/:voting_pubkey`](#patch-lighthousevalidatorsvoting_pubkey) | Update a specific validator.
[`POST /lighthouse/validators`](#post-lighthousevalidators) | Create a new validator and mnemonic.
[`POST /lighthouse/validators/keystore`](#post-lighthousevalidatorskeystore) | Import a keystore.
[`POST /lighthouse/validators/mnemonic`](#post-lighthousevalidatorsmnemonic) | Create a new validator from an existing mnemonic.
[`POST /lighthouse/validators/web3signer`](#post-lighthousevalidatorsweb3signer) | Add web3signer validators.

The query to Lighthouse API endpoints requires authorization, see [Authorization Header](./api-vc-auth-header.md). 

In addition to the above endpoints Lighthouse also supports all of the [standard keymanager APIs](https://ethereum.github.io/keymanager-APIs/).


## `GET /lighthouse/version`

Returns the software version and `git` commit hash for the Lighthouse binary.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/version`                      |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/version" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
```

Example Response Body:


```json
{
    "data": {
        "version": "Lighthouse/v4.1.0-693886b/x86_64-linux"
    }
}
```
> Note: The command provided in this documentation links to the API token file. In this documentation, it is assumed that the API token file is located in `/var/lib/lighthouse/validators/API-token.txt`. If your database is saved in another directory, modify the `DATADIR` accordingly. If you are having permission issue with accessing the API token file, you can modify the header to become `-H "Authorization: Bearer $(sudo cat ${DATADIR}/validators/api-token.txt)"`.

> As an alternative, you can also provide the API token directly, for example, `-H "Authorization: Bearer api-token-0x02dc2a13115cc8c83baf170f597f22b1eb2930542941ab902df3daadebcb8f8176`. In this case, you obtain the token from the file `API token.txt` and the command becomes:
```bash
curl -X GET "http://localhost:5062/lighthouse/version" -H "Authorization: Bearer api-token-0x02dc2a13115cc8c83baf170f597f22b1eb2930542941ab902df3daadebcb8f8176" | jq
```

## `GET /lighthouse/health`

Returns information regarding the health of the host machine.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/health`                       |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

*Note: this endpoint is presently only available on Linux.*

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/health" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
```

Example Response Body:

```json
{
  "data": {
    "sys_virt_mem_total": 8184274944,
    "sys_virt_mem_available": 1532280832,
    "sys_virt_mem_used": 6248341504,
    "sys_virt_mem_free": 648790016,
    "sys_virt_mem_percent": 81.27775,
    "sys_virt_mem_cached": 1244770304,
    "sys_virt_mem_buffers": 42373120,
    "sys_loadavg_1": 2.33,
    "sys_loadavg_5": 2.11,
    "sys_loadavg_15": 2.47,
    "cpu_cores": 4,
    "cpu_threads": 8,
    "system_seconds_total": 103095,
    "user_seconds_total": 750734,
    "iowait_seconds_total": 60671,
    "idle_seconds_total": 3922305,
    "cpu_time_total": 4794222,
    "disk_node_bytes_total": 982820896768,
    "disk_node_bytes_free": 521943703552,
    "disk_node_reads_total": 376287830,
    "disk_node_writes_total": 48232652,
    "network_node_bytes_total_received": 143003442144,
    "network_node_bytes_total_transmit": 185348289905,
    "misc_node_boot_ts_seconds": 1681740973,
    "misc_os": "linux",
    "pid": 144072,
    "pid_num_threads": 27,
    "pid_mem_resident_set_size": 15835136,
    "pid_mem_virtual_memory_size": 2179018752,
    "pid_process_seconds_total": 54
  }
}
```

## `GET /lighthouse/ui/health`

Returns information regarding the health of the host machine.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/ui/health`                       |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/ui/health" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
 ```

Example Response Body

```json
{
  "data": {
    "total_memory": 16443219968,
    "free_memory": 1283739648,
    "used_memory": 5586264064,
    "sys_loadavg_1": 0.59,
    "sys_loadavg_5": 1.13,
    "sys_loadavg_15": 2.41,
    "cpu_cores": 4,
    "cpu_threads": 8,
    "global_cpu_frequency": 3.4,
    "disk_bytes_total": 502390845440,
    "disk_bytes_free": 9981386752,
    "system_uptime": 660706,
    "app_uptime": 105,
    "system_name": "Arch Linux",
    "kernel_version": "5.19.13-arch1-1",
    "os_version": "Linux rolling Arch Linux",
    "host_name": "Computer1"
  }
}
```

## `GET /lighthouse/ui/graffiti`

Returns the graffiti that will be used for the next block proposal of each validator.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/ui/graffiti`                    |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/ui/graffiti" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
 ```
Example Response Body

```json
{
  "data": {
    "0x81283b7a20e1ca460ebd9bbd77005d557370cabb1f9a44f530c4c4c66230f675f8df8b4c2818851aa7d77a80ca5a4a5e": "mr f was here",
    "0xa3a32b0f8b4ddb83f1a0a853d81dd725dfe577d4f4c3db8ece52ce2b026eca84815c1a7e8e92a4de3d755733bf7e4a9b": "mr v was here",
    "0x872c61b4a7f8510ec809e5b023f5fdda2105d024c470ddbbeca4bc74e8280af0d178d749853e8f6a841083ac1b4db98f": null
  }
}
```

## `GET /lighthouse/spec`

Returns the Ethereum proof-of-stake consensus specification loaded for this validator.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/spec`                         |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/spec" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
```

Example Response Body

```json
{
  "data": {
    "CONFIG_NAME": "prater",
    "PRESET_BASE": "mainnet",
    "TERMINAL_TOTAL_DIFFICULTY": "10790000",
    "TERMINAL_BLOCK_HASH": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH": "18446744073709551615",
    "SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY": "128",
    "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT": "16384",
    "MIN_GENESIS_TIME": "1614588812",
    "GENESIS_FORK_VERSION": "0x00001020",
    "GENESIS_DELAY": "1919188",
    "ALTAIR_FORK_VERSION": "0x01001020",
    "ALTAIR_FORK_EPOCH": "36660",
    "BELLATRIX_FORK_VERSION": "0x02001020",
    "BELLATRIX_FORK_EPOCH": "112260",
    "CAPELLA_FORK_VERSION": "0x03001020",
    "CAPELLA_FORK_EPOCH": "162304",
    "SECONDS_PER_SLOT": "12",
    "SECONDS_PER_ETH1_BLOCK": "14",
    "MIN_VALIDATOR_WITHDRAWABILITY_DELAY": "256",
    "SHARD_COMMITTEE_PERIOD": "256",
    "ETH1_FOLLOW_DISTANCE": "2048",
    "INACTIVITY_SCORE_BIAS": "4",
    "INACTIVITY_SCORE_RECOVERY_RATE": "16",
    "EJECTION_BALANCE": "16000000000",
    "MIN_PER_EPOCH_CHURN_LIMIT": "4",
    "CHURN_LIMIT_QUOTIENT": "65536",
    "PROPOSER_SCORE_BOOST": "40",
    "DEPOSIT_CHAIN_ID": "5",
    "DEPOSIT_NETWORK_ID": "5",
    "DEPOSIT_CONTRACT_ADDRESS": "0xff50ed3d0ec03ac01d4c79aad74928bff48a7b2b",
    "MAX_COMMITTEES_PER_SLOT": "64",
    "TARGET_COMMITTEE_SIZE": "128",
    "MAX_VALIDATORS_PER_COMMITTEE": "2048",
    "SHUFFLE_ROUND_COUNT": "90",
    "HYSTERESIS_QUOTIENT": "4",
    "HYSTERESIS_DOWNWARD_MULTIPLIER": "1",
    "HYSTERESIS_UPWARD_MULTIPLIER": "5",
    "SAFE_SLOTS_TO_UPDATE_JUSTIFIED": "8",
    "MIN_DEPOSIT_AMOUNT": "1000000000",
    "MAX_EFFECTIVE_BALANCE": "32000000000",
    "EFFECTIVE_BALANCE_INCREMENT": "1000000000",
    "MIN_ATTESTATION_INCLUSION_DELAY": "1",
    "SLOTS_PER_EPOCH": "32",
    "MIN_SEED_LOOKAHEAD": "1",
    "MAX_SEED_LOOKAHEAD": "4",
    "EPOCHS_PER_ETH1_VOTING_PERIOD": "64",
    "SLOTS_PER_HISTORICAL_ROOT": "8192",
    "MIN_EPOCHS_TO_INACTIVITY_PENALTY": "4",
    "EPOCHS_PER_HISTORICAL_VECTOR": "65536",
    "EPOCHS_PER_SLASHINGS_VECTOR": "8192",
    "HISTORICAL_ROOTS_LIMIT": "16777216",
    "VALIDATOR_REGISTRY_LIMIT": "1099511627776",
    "BASE_REWARD_FACTOR": "64",
    "WHISTLEBLOWER_REWARD_QUOTIENT": "512",
    "PROPOSER_REWARD_QUOTIENT": "8",
    "INACTIVITY_PENALTY_QUOTIENT": "67108864",
    "MIN_SLASHING_PENALTY_QUOTIENT": "128",
    "PROPORTIONAL_SLASHING_MULTIPLIER": "1",
    "MAX_PROPOSER_SLASHINGS": "16",
    "MAX_ATTESTER_SLASHINGS": "2",
    "MAX_ATTESTATIONS": "128",
    "MAX_DEPOSITS": "16",
    "MAX_VOLUNTARY_EXITS": "16",
    "INACTIVITY_PENALTY_QUOTIENT_ALTAIR": "50331648",
    "MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR": "64",
    "PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR": "2",
    "SYNC_COMMITTEE_SIZE": "512",
    "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": "256",
    "MIN_SYNC_COMMITTEE_PARTICIPANTS": "1",
    "INACTIVITY_PENALTY_QUOTIENT_BELLATRIX": "16777216",
    "MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX": "32",
    "PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX": "3",
    "MAX_BYTES_PER_TRANSACTION": "1073741824",
    "MAX_TRANSACTIONS_PER_PAYLOAD": "1048576",
    "BYTES_PER_LOGS_BLOOM": "256",
    "MAX_EXTRA_DATA_BYTES": "32",
    "MAX_BLS_TO_EXECUTION_CHANGES": "16",
    "MAX_WITHDRAWALS_PER_PAYLOAD": "16",
    "MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP": "16384",
    "DOMAIN_DEPOSIT": "0x03000000",
    "BLS_WITHDRAWAL_PREFIX": "0x00",
    "RANDOM_SUBNETS_PER_VALIDATOR": "1",
    "DOMAIN_SYNC_COMMITTEE": "0x07000000",
    "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE": "16",
    "DOMAIN_BEACON_ATTESTER": "0x01000000",
    "DOMAIN_VOLUNTARY_EXIT": "0x04000000",
    "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF": "0x08000000",
    "DOMAIN_CONTRIBUTION_AND_PROOF": "0x09000000",
    "EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION": "256",
    "TARGET_AGGREGATORS_PER_COMMITTEE": "16",
    "DOMAIN_APPLICATION_MASK": "0x00000001",
    "DOMAIN_AGGREGATE_AND_PROOF": "0x06000000",
    "DOMAIN_RANDAO": "0x02000000",
    "DOMAIN_SELECTION_PROOF": "0x05000000",
    "DOMAIN_BEACON_PROPOSER": "0x00000000",
    "SYNC_COMMITTEE_SUBNET_COUNT": "4"
  }
}
```

## `GET /lighthouse/auth`

Fetch the filesystem path of the [authorization token](./api-vc-auth-header.md).
Unlike the other endpoints this may be called _without_ providing an authorization token.

This API is intended to be called from the same machine as the validator client, so that the token
file may be read by a local user with access rights.

### HTTP Specification

| Property          | Specification      |
|-------------------|--------------------|
| Path              | `/lighthouse/auth` |
| Method            | GET                |
| Required Headers  | -                  |
| Typical Responses | 200                |

Command:

```bash
curl http://localhost:5062/lighthouse/auth | jq
```

Example Response Body

```json
{
    "token_path": "/home/karlm/.lighthouse/prater/validators/api-token.txt"
}
```

## `GET /lighthouse/validators`

Lists all validators managed by this validator client.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators`                   |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/validators/" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
```

Example Response Body

```json
{
    "data": [
        {
            "enabled": true,
            "description": "validator one",
            "voting_pubkey": "0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde"
        },
        {
            "enabled": true,
            "description": "validator two",
            "voting_pubkey": "0xb0441246ed813af54c0a11efd53019f63dd454a1fa2a9939ce3c228419fbe113fb02b443ceeb38736ef97877eb88d43a"
        },
        {
            "enabled": true,
            "description": "validator three",
            "voting_pubkey": "0xad77e388d745f24e13890353031dd8137432ee4225752642aad0a2ab003c86620357d91973b6675932ff51f817088f38"
        }
    ]
}
```

## `GET /lighthouse/validators/:voting_pubkey`

Get a validator by their `voting_pubkey`.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/:voting_pubkey`    |
| Method            | GET                                        |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200, 400                                   |

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X GET "http://localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde" -H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" | jq
```

Example Response Body

```json
{
    "data": {
        "enabled": true,
        "voting_pubkey": "0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde"
    }
}
```

## `PATCH /lighthouse/validators/:voting_pubkey`

Update some values for the validator with `voting_pubkey`. Possible fields: `enabled`, `gas_limit`, `builder_proposals`, 
and `graffiti`.  The following example updates a validator from `enabled: true` to `enabled: false`.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/:voting_pubkey`    |
| Method            | PATCH                                      |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200, 400                                   |


Example Request Body

```json
{
    "enabled": false
}
```

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X PATCH "http://localhost:5062/lighthouse/validators/0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde" \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d "{\"enabled\":false}" | jq
```
### Example Response Body

```json
null
```

A `null` response indicates that the request is successful. At the same time, `lighthouse vc` will log:

```
INFO Disabled validator                      voting_pubkey: 0xb0148e6348264131bf47bcd1829590e870c836dc893050fd0dadc7a28949f9d0a72f2805d027521b45441101f0cc1cde
INFO Modified key_cache saved successfully
```


## `POST /lighthouse/validators/`

Create any number of new validators, all of which will share a common mnemonic
generated by the server.

A BIP-39 mnemonic will be randomly generated and returned with the response.
This mnemonic can be used to recover all keys returned in the response.
Validators are generated from the mnemonic according to
[EIP-2334](https://eips.ethereum.org/EIPS/eip-2334), starting at index `0`.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators`                   |
| Method            | POST                                       |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

### Example Request Body

```json
[
    {
        "enable": true,
        "description": "validator_one",
        "deposit_gwei": "32000000000",
        "graffiti": "Mr F was here",
        "suggested_fee_recipient": "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
    },
    {
        "enable": false,
        "description": "validator two",
        "deposit_gwei": "34000000000"
    }
]
```

Command: 
```bash
DATADIR=/var/lib/lighthouse
curl -X POST http://localhost:5062/lighthouse/validators \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d '[
    {
        "enable": true,
        "description": "validator_one",
        "deposit_gwei": "32000000000",
        "graffiti": "Mr F was here",
        "suggested_fee_recipient": "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"
    },
    {
        "enable": false,
        "description": "validator two",
        "deposit_gwei": "34000000000"
    }
]' | jq
```

### Example Response Body

```json
{
    "data": {
        "mnemonic": "marine orchard scout label trim only narrow taste art belt betray soda deal diagram glare hero scare shadow ramp blur junior behave resource tourist",
        "validators": [
            {
                "enabled": true,
                "description": "validator_one",
                "voting_pubkey": "0x8ffbc881fb60841a4546b4b385ec5e9b5090fd1c4395e568d98b74b94b41a912c6101113da39d43c101369eeb9b48e50",
                "eth1_deposit_tx_data": "0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001206c68675776d418bfd63468789e7c68a6788c4dd45a3a911fe3d642668220bbf200000000000000000000000000000000000000000000000000000000000000308ffbc881fb60841a4546b4b385ec5e9b5090fd1c4395e568d98b74b94b41a912c6101113da39d43c101369eeb9b48e5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000cf8b3abbf0ecd91f3b0affcc3a11e9c5f8066efb8982d354ee9a812219b17000000000000000000000000000000000000000000000000000000000000000608fbe2cc0e17a98d4a58bd7a65f0475a58850d3c048da7b718f8809d8943fee1dbd5677c04b5fa08a9c44d271d009edcd15caa56387dc217159b300aad66c2cf8040696d383d0bff37b2892a7fe9ba78b2220158f3dc1b9cd6357bdcaee3eb9f2",
                "deposit_gwei": "32000000000"
            },
            {
                "enabled": false,
                "description": "validator two",
                "voting_pubkey": "0xa9fadd620dc68e9fe0d6e1a69f6c54a0271ad65ab5a509e645e45c6e60ff8f4fc538f301781193a08b55821444801502",
                "eth1_deposit_tx_data": "0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120b1911954c1b8d23233e0e2bf8c4878c8f56d25a4f790ec09a94520ec88af30490000000000000000000000000000000000000000000000000000000000000030a9fadd620dc68e9fe0d6e1a69f6c54a0271ad65ab5a509e645e45c6e60ff8f4fc538f301781193a08b5582144480150200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000a96df8b95c3ba749265e48a101f2ed974fffd7487487ed55f8dded99b617ad000000000000000000000000000000000000000000000000000000000000006090421299179824950e2f5a592ab1fdefe5349faea1e8126146a006b64777b74cce3cfc5b39d35b370e8f844e99c2dc1b19a1ebd38c7605f28e9c4540aea48f0bc48e853ae5f477fa81a9fc599d1732968c772730e1e47aaf5c5117bd045b788e",
                "deposit_gwei": "34000000000"
            }
        ]
    }
}
```

 `lighthouse vc` will log:

```
INFO Enabled validator                      voting_pubkey: 0x8ffbc881fb60841a4546b4b385ec5e9b5090fd1c4395e568d98b74b94b41a912c6101113da39d43c101369eeb9b48e50, signing_method: local_keystore
INFO Modified key_cache saved successfully
INFO Disabled validator                     voting_pubkey: 0xa9fadd620dc68e9fe0d6e1a69f6c54a0271ad65ab5a509e645e45c6e60ff8f4fc538f301781193a08b55821444801502
```

## `POST /lighthouse/validators/keystore`

Import a keystore into the validator client.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/keystore`          |
| Method            | POST                                       |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

### Example Request Body

```json
{
  "enable": true,
  "password": "mypassword",
  "keystore": {
    "crypto": {
      "kdf": {
        "function": "scrypt",
        "params": {
          "dklen": 32,
          "n": 262144,
          "r": 8,
          "p": 1,
          "salt": "445989ec2f332bb6099605b4f1562c0df017488d8d7fb3709f99ebe31da94b49"
        },
        "message": ""
      },
      "checksum": {
        "function": "sha256",
        "params": {

        },
        "message": "abadc1285fd38b24a98ac586bda5b17a8f93fc1ff0778803dc32049578981236"
      },
      "cipher": {
        "function": "aes-128-ctr",
        "params": {
          "iv": "65abb7e1d02eec9910d04299cc73efbe"
        },
        "message": "6b7931a4447be727a3bb5dc106d9f3c1ba50671648e522f213651d13450b6417"
      }
    },
    "uuid": "5cf2a1fb-dcd6-4095-9ebf-7e4ee0204cab",
    "path": "m/12381/3600/0/0/0",
    "pubkey": "b0d2f05014de27c6d7981e4a920799db1c512ee7922932be6bf55729039147cf35a090bd4ab378fe2d133c36cbbc9969",
    "version": 4,
    "description": ""
  }
}
```

We can use [JSON to String Converter](https://jsontostring.com/) so that the above data can be properly presented as a command. The command is as below:

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X POST http://localhost:5062/lighthouse/validators/keystore \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d "{\"enable\":true,\"password\":\"mypassword\",\"keystore\":{\"crypto\":{\"kdf\":{\"function\":\"scrypt\",\"params\":{\"dklen\":32,\"n\":262144,\"r\":8,\"p\":1,\"salt\":\"445989ec2f332bb6099605b4f1562c0df017488d8d7fb3709f99ebe31da94b49\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},\"message\":\"abadc1285fd38b24a98ac586bda5b17a8f93fc1ff0778803dc32049578981236\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\"65abb7e1d02eec9910d04299cc73efbe\"},\"message\":\"6b7931a4447be727a3bb5dc106d9f3c1ba50671648e522f213651d13450b6417\"}},\"uuid\":\"5cf2a1fb-dcd6-4095-9ebf-7e4ee0204cab\",\"path\":\"m/12381/3600/0/0/0\",\"pubkey\":\"b0d2f05014de27c6d7981e4a920799db1c512ee7922932be6bf55729039147cf35a090bd4ab378fe2d133c36cbbc9969\",\"version\":4,\"description\":\"\"}}" | jq
```

As this is an example for demonstration, the above command will return `InvalidPassword`. However, with a keystore file and correct password, running the above command will import the keystore to the validator client. An example of a success message is shown below:

### Example Response Body
```json
{
  "data": {
    "enabled": true,
    "description": "",
    "voting_pubkey": "0xb0d2f05014de27c6d7981e4a920799db1c512ee7922932be6bf55729039147cf35a090bd4ab378fe2d133c36cbbc9969"
  }
}

```

 `lighthouse vc` will log:

```bash
INFO Enabled validator                      voting_pubkey: 0xb0d2f05014de27c6d7981e4a920799db1c512ee7922932be6bf55729039147cf35a090bd4ab378fe2d133c36cbb, signing_method: local_keystore
INFO Modified key_cache saved successfully
```

## `POST /lighthouse/validators/mnemonic`

Create any number of new validators, all of which will share a common mnemonic.

The supplied BIP-39 mnemonic will be used to generate the validator keys
according to [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334), starting at
the supplied `key_derivation_path_offset`. For example, if
`key_derivation_path_offset = 42`, then the first validator voting key will be
generated with the path `m/12381/3600/i/42`.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/mnemonic`          |
| Method            | POST                                       |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200                                        |

### Example Request Body

```json
{
    "mnemonic": "theme onion deal plastic claim silver fancy youth lock ordinary hotel elegant balance ridge web skill burger survey demand distance legal fish salad cloth",
    "key_derivation_path_offset": 0,
    "validators": [
        {
            "enable": true,
            "description": "validator_one",
            "deposit_gwei": "32000000000"
        }
    ]
}
```

Command:

```bash
DATADIR=/var/lib/lighthouse
curl -X POST http://localhost:5062/lighthouse/validators/mnemonic \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d '{"mnemonic":" theme onion deal plastic claim silver fancy youth lock ordinary hotel elegant balance ridge web skill burger survey demand distance legal fish salad cloth","key_derivation_path_offset":0,"validators":[{"enable":true,"description":"validator_one","deposit_gwei":"32000000000"}]}' | jq
```

### Example Response Body

```json
{
    "data": [
        {
            "enabled": true,
            "description": "validator_one",
            "voting_pubkey": "0xa062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db380",
            "eth1_deposit_tx_data": "0x22895118000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120a57324d95ae9c7abfb5cc9bd4db253ed0605dc8a19f84810bcf3f3874d0e703a0000000000000000000000000000000000000000000000000000000000000030a062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db3800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200046e4199f18102b5d4e8842d0eeafaa1268ee2c21340c63f9c2cd5b03ff19320000000000000000000000000000000000000000000000000000000000000060b2a897b4ba4f3910e9090abc4c22f81f13e8923ea61c0043506950b6ae174aa643540554037b465670d28fa7b7d716a301e9b172297122acc56be1131621c072f7c0a73ea7b8c5a90ecd5da06d79d90afaea17cdeeef8ed323912c70ad62c04b",
            "deposit_gwei": "32000000000"
        }
    ]
}
```

`lighthouse vc` will log:

```
INFO Enabled validator                       voting_pubkey: 0xa062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db380, signing_method: local_keystore
INFO Modified key_cache saved successfully
```

## `POST /lighthouse/validators/web3signer`

Create any number of new validators, all of which will refer to a
[Web3Signer](https://docs.web3signer.consensys.net/en/latest/) server for signing.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/validators/web3signer`        |
| Method            | POST                                       |
| Required Headers  | [`Authorization`](./api-vc-auth-header.md) |
| Typical Responses | 200, 400                                   |

### Example Request Body

```json
[
    {
        "enable": true,
        "description": "validator_one",
        "graffiti": "Mr F was here",
        "suggested_fee_recipient": "0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d",
        "voting_public_key": "0xa062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db380",
        "url": "http://path-to-web3signer.com",
        "root_certificate_path": "/path/on/vc/filesystem/to/certificate.pem",
        "request_timeout_ms": 12000
    }
]
```

The following fields may be omitted or nullified to obtain default values:

- `graffiti`
- `suggested_fee_recipient`
- `root_certificate_path`
- `request_timeout_ms`

Command:
```bash
DATADIR=/var/lib/lighthouse
curl -X POST http://localhost:5062/lighthouse/validators/web3signer \
-H "Authorization: Bearer $(cat ${DATADIR}/validators/api-token.txt)" \
-H "Content-Type: application/json" \
-d "[{\"enable\":true,\"description\":\"validator_one\",\"graffiti\":\"Mr F was here\",\"suggested_fee_recipient\":\"0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d\",\"voting_public_key\":\"0xa062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db380\",\"url\":\"http://path-to-web3signer.com\",\"request_timeout_ms\":12000}]"
```


### Example Response Body


```json
null
```

A `null` response indicates that the request is successful. At the same time, `lighthouse vc` will log:

```
INFO Enabled validator                       voting_pubkey: 0xa062f95fee747144d5e511940624bc6546509eeaeae9383257a9c43e7ddc58c17c2bab4ae62053122184c381b90db380, signing_method: remote_signer
```


## `GET /lighthouse/logs`

Provides a subscription to receive logs as Server Side Events. Currently the
logs emitted are INFO level or higher.

### HTTP Specification

| Property          | Specification                              |
|-------------------|--------------------------------------------|
| Path              | `/lighthouse/logs`                         |
| Method            | GET                                        |
| Required Headers  | None                                       |
| Typical Responses | 200                                        |

### Example Response Body

```json
{
  "data": {
	  "time": "Mar 13 15:26:53",
	  "level": "INFO",
	  "msg": "Connected to beacon node(s)",
	  "service": "notifier",
	  "synced": 1,
	  "available": 1,
	  "total": 1
  }
}
```

# Remote BLS Signer

## Overview

Simple HTTP BLS signer service.

This service is designed to be consumed by Ethereum 2.0 clients, looking for a more secure avenue to store their BLS12-381 secret keys, while running their validators in more permisive and/or scalable environments.

One goal of this package is to be standard compliant. There is a [current draft for an Ethereum Improvement Proposal (EIP)](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3030.md) in progress. Please refer to the [wishlist](#wishlist--roadmap) in this very document for a list of advanced features.

## API

### Standard

### `GET /upcheck`

_**Responses**_

Success | <br>
--- | ---
Code | `200`
Content | `{"status": "OK"}`

---

### `GET /keys`

Returns the identifiers of the keys available to the signer.

_**Responses**_

Success | <br>
--- | ---
Code | `200`
Content | `{"keys": "[identifier]"}`

---

### `POST /sign/:identifier`

URL Parameter | <br>
--- | ---
`:identifier` | `public_key_hex_string_without_0x`

_**Request**_

JSON Body | <br> | <br>
--- | --- | ---
`bls_domain` | **Required** | The BLS Signature domain.<br>As defined in the [specification](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#domain-types), in lowercase, omitting the `domain` prefix.<br>Supporting `beacon_proposer`, `beacon_attester`, and `randao`.
`data` | **Required** | The data to be signed.<br>As defined in the specifications for [block](https://github.com/ethereum/eth2.0-APIs/blob/master/types/block.yaml), [attestation](https://github.com/ethereum/eth2.0-APIs/blob/master/types/attestation.yaml), and [epoch](https://github.com/ethereum/eth2.0-APIs/blob/master/types/misc.yaml).
`fork` | **Required** | A `Fork` object containing previous and current versions.<br>As defined in the [specification](https://github.com/ethereum/eth2.0-APIs/blob/master/types/misc.yaml)
`genesis_validators_root` | **Required** | A `Hash256` for domain separation and chain versioning.
<br> | Optional | Any other field will be ignored by the signer

_**Responses**_

Success | <br>
--- | ---
Code |  `200`
Content | `{"signature": "<signature_hex_string>"}`

_or_

Error | <br>
--- | ---
Code |  `400`
Content | `{"error": "<Bad Request Error Message>"}`

_or_

Error | <br>
--- | ---
Code |  `404`
Content | `{"error": "Key not found: <identifier>"}`

## Build instructions

1. [Get Rust](https://www.rust-lang.org/learn/get-started).
2. Go to the root directory of this repository.
3. Execute `make`
4. The binary `lighthouse` will most likely be found in `./target/release`.
5. Run it as `lighthouse remote_signer` or `lighthouse rs`.

## Running the signer

### Storing the secret keys as raw files

* Steps to store a secret key
  * Choose an empty directory, as the backend will parse every file looking for keys.
  * Create a file named after the **hex representation of the public key without 0x**.
  * Write the **hex representation of the secret key without 0x**.
  * Store the file in your chosen directory.
  * Use this directory as a command line parameter (`--storage-raw-dir`)

### Command line flags

```
USAGE:
    remote_signer [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --debug-level <LEVEL>         The verbosity level for emitting logs. [default: info]  [possible values:
                                      info, debug, trace, warn, error, crit]
        --listen-address <ADDRESS>    The address to listen for TCP connections. [default: 0.0.0.0]
        --log-format <FORMAT>         Specifies the format used for logging. [possible values: JSON]
        --logfile <FILE>              File path where output will be written.
        --port <PORT>                 The TCP port to listen on. [default: 9000]
        --spec <TITLE>                Specifies the default eth2 spec type. [default: mainnet]  [possible values:
                                      mainnet, minimal, interop]
        --storage-raw-dir <DIR>       Data directory for secret keys in raw files.
```

## Roadmap

- [X] EIP standard compliant
- [ ] Metrics
- [ ] Benchmarking & Profiling
- [ ] Release management
- [ ] Architecture builds
- [ ] Support EIP-2335, BLS12-381 keystore
- [ ] Support storage in AWS Cloud HSM
- [ ] Route with the `warp` library
- [ ] Filter by the `message` field
  - [ ] Middleware REST API
  - [ ] Built-in middleware
  - [ ] Flag to enforce the `message` field and compare it to the signing root
- [ ] TLS/SSL support for requests
- [ ] Authentication by HTTP Header support
- [ ] Confidential computing support (e.g. Intel SGX)

## LICENSE

* Apache 2.0.

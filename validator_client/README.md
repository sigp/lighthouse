# Lighthouse Validator Client

The Validator Client (VC) is a stand-alone binary which connects to a Beacon
Node (BN) and fulfils the roles of a validator.

## Roles

The VC is responsible for the following tasks:

- Requesting validator duties (a.k.a. shuffling) from the BN.
- Prompting the BN to produce a new block, when a validators block production
	duties require.
- Completing all the fields on a new block (e.g., RANDAO reveal, signature) and
	publishing the block to a BN.
- Prompting the BN to produce a new shard attestation as per a validators
	duties.
- Ensuring that no slashable messages are signed by a validator private key.
- Keeping track of the system clock and how it relates to slots/epochs.

The VC is capable of managing multiple validators in the same process tree.

## Implementation

_This section describes the present implementation of this VC binary._

### Services

Each validator is represented by two services, one which tracks the validator
duties and another which performs block production duties.

A separate thread is maintained for each service, for each validator. As such,
a single validator utilises three (3) threads (one for the base VC and two for
each service) and two validators utilise five (5) threads.

#### `DutiesManagerService`

Polls a BN and requests validator responsibilities, as well as a validator
index. The outcome of a successful poll is a `EpochDuties` struct:

```rust
EpochDuties {
	validator_index: u64,
	block_production_slot: u64,
}
```

This is stored in the `EpochDutiesMap`, a `HashMap` mapping `epoch ->
EpochDuties`.

#### `BlockProducerService`

Polls the system clock and determines if a block needs to be produced. Reads
from the `EpochDutiesMap` maintained by the `DutiesManagerService`.

If block production is required, performs all the necessary duties to request,
complete and return a block from the BN.

### Configuration

Validator configurations are stored in a separate data directory from the main Beacon Node
binary. The validator data directory defaults to:
`$HOME/.lighthouse-validator`, however an alternative can be specified on the command line
with `--datadir`.

The configuration directory structure looks like:
```
~/.lighthouse-validator
    ├── 3cf4210d58ec
    │   └── private.key
    ├── 9b5d8b5be4e7
    │   └── private.key
    └── cf6e07188f48
        └── private.key
```

Where the hex value of the directory is a portion of the validator public key.

Validator keys must be generated using the separate `account_manager` binary, which will
place the keys into this directory structure in a format compatible with the validator client.
Be sure to check the readme for `account_manager`.

The chain specification (slot length, BLS domain, etc.) defaults to foundation
parameters, however is temporary and an upgrade will allow these parameters to be
read from a file (or initialized on first-boot).

## BN Communication

The VC communicates with the BN via a gRPC/protobuf connection.

# Lighthouse Validator Client

The Validator Client (VC) is a stand-alone binary which connects to a Beacon
Node (BN) and fulfils the roles of a validator.

## Roles

The VC is responsible for the following tasks:

- Requesting validator duties (a.k.a. shuffling) from the BN.
- Prompting the BN to propose a new block, when a validators block production
	duties require.
- Completing all the fields on a new block (e.g., RANDAO reveal, signature) and
	publishing the block to a BN.
- Prompting the BN to propose a new shard atteststation as per a validators
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
	block_prodcution_slot: u64,
}
```

This is stored in the `EpochDutiesMap`, a `HashMap` mapping `epoch ->
EpochDuties`.

#### `BlockProposerService`

Polls the system clock and determines if a block needs to be proposed. Reads
from the `EpochDutiesMap` maintained by the `DutiesManagerService`.

If block production is required, performs all the necessary duties to request,
complete and return a block from the BN.

### Configuration

Presently the validator specifics (pubkey, etc.) are randomly generated and the
chain specification (slot length, BLS domain, etc.) are fixed to foundation
parameters. This is temporary and will be upgrade so these parameters can be
read from file (or initialized on first-boot).

## BN Communication

The VC communicates with the BN via a gRPC/protobuf connection.

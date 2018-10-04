# Lighthouse: an Ethereum 2.0 client

[![Build Status](https://travis-ci.org/sigp/lighthouse.svg?branch=master)](https://travis-ci.org/sigp/lighthouse) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sigp/lighthouse?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

A work-in-progress, open-source implementation of the Ethereum 2.0 Beacon Chain, maintained
by Sigma Prime.

## Introduction

Lighthouse is an open-source Ethereum 2.0 client, in development. Designed as
an Ethereum 2.0-only client, Lighthouse will not re-implement the existing
proof-of-work protocol. Maintaining a forward-focus on Ethereum 2.0 ensures
that Lighthouse will avoid reproducing the high-quality work already undertaken
by existing clients.

This readme is split into two major sections:

- [Lighthouse Client](#lighthouse-client): information about this
  implemenation.
- [What is Ethereum 2.0](#what-is-ethereum-20): an introduction to Ethereum 2.0.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post.

## Lighthouse Client


### Goals

We aim to contribute to the research and development of a secure, efficient and
decentralised Ethereum protocol through the development of an open-source
Ethereum 2.0 client.

In addition to building an implementation, we seek to help maintain and improve
the protocol wherever possible.

### Components

The following list describes some of the components actively under development
by the team:

- **BLS cryptography**: we presently use the [Apache
  Milagro](https://milagro.apache.org/) cryptography library to create and
verify BLS aggregate signatures. BLS signatures are core to Eth 2.0 as they
allow the signatures of many validators to be compressed into a constant 96
bytes and verified efficiently.. We're presently maintaining our own [BLS
aggregates library](https://github.com/sigp/signature-schemes), gratefully
forked from @lovesh.
- **DoS-resistant block pre-processing**: processing blocks in proof-of-stake
  is more resource intensive than proof-of-work. As such, clients need to
ensure that bad blocks can be rejected as efficiently as possible. We can
presently process a block with 10 million ETH staked in 0.006 seconds and
reject invalid blocks even quicker. See the
[issue](https://github.com/ethereum/beacon_chain/issues/103) on
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain)
.
- **P2P networking**: Eth 2.0 will likely use the [libp2p
  framework](https://libp2p.io/). Lighthouse aims to work alongside
[Parity](https://www.parity.io/) to get
[libp2p-rust](https://github.com/libp2p/rust-libp2p) fit-for-purpose.
- **Validator duties** : the project involves the development of "validator"
  services for users who wish to stake ETH. To fulfil their duties, validators
require a consistent view of the chain and the ability to vote upon both shard
and beacon chain blocks..
- **New serialization formats**: lighthouse is working alongside EF researchers
  to develop "simpleserialize" a purpose-built serialization format for sending
information across the network. Check out our [SSZ
implementation](https://github.com/sigp/lighthouse/tree/master/beacon_chain/utils/ssz)
and our
[research](https://github.com/sigp/serialization_sandbox/blob/report/report/serialization_report.md)
on serialization formats.
- **Casper FFG fork-choice**: the [Casper
  FFG](https://arxiv.org/abs/1710.09437) fork-choice rules allow the chain to
select a canonical chain in the case of a fork.
- **Efficient state transition logic**: "state transition" logic governs
  updates to the validator set as validators log in/out, penalises/rewards
validators, rotates validators across shards, and implements other core tasks.
- **Fuzzing and testing environments**: we are preparing to implement lab
environments with CI work-flows to provide automated security analysis..

In addition to these components we're also working on database schemas, RPC
frameworks, specification development, database optimizations (e.g.,
bloom-filters) and tons of other interesting stuff (at least we think so).

### Contributing

**Lighthouse welcomes contributors with open-arms.**

Layer-1 infrastructure is a critical component of the ecosystem and relies
heavily on community contribution. Building Ethereum 2.0 is a huge task and we
refuse to "do an ICO" or charge licensing fees. Instead, we fund development
through grants and support from Sigma Prime.

If you would like to learn more about Ethereum 2.0 and/or
[Rust](https://www.rust-lang.org/), we would be more than happy to on-board you
and assign you to some tasks. We aim to be as accepting and understanding as
possible; we are more than happy to up-skill contributors in exchange for their
help on the project.

Alternatively, if you an ETH/Rust veteran we'd love to have your input.  We're
always looking for the best way to implement things and will consider any
respectful criticism.

If you'd like to contribute, try having a look through the [open
issues](https://github.com/sigp/lighthouse/issues) (tip: look for the [good
first
issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
tag) and ping us on the [gitter](https://gitter.im/sigp/lighthouse). We need
your support!

### Running

**NOTE: the cryptography libraries used in this implementation are
experimental and as such all cryptography should be assumed to be insecure.**

The code-base is still under-development and does not provide any user-facing
functionality. For developers and researchers, there are tests and benchmarks
which could be of interest.

To run tests, use

```
$ cargo test --all
```

To run benchmarks, use

```
$ cargo bench --all
```

Lighthouse presently runs on Rust `stable`, however, benchmarks require the
`nightly` version.

### Engineering Ethos

Lighthouse aims to produce many small, easily-tested components, each separated
into individual crates wherever possible.

Generally, tests can be kept in the same file, as is typical in Rust.
Integration tests should be placed in the `tests` directory in the crates root.
Particularity large (line-count) tests should be separated into another file.

A function is not complete until it is tested. We produce tests to protect
against regression (accidentally breaking things) and to help those who read
our code to understand how the function should (or shouldn't) be used.

Each PR is to be reviewed by at-least one "core developer" (i.e., someone with
write-access to the repository). This helps to detect bugs, improve consistency
and relieves any one individual of the responsibility of an error.

Discussion should be respectful and intellectual. Have fun, make jokes but
respect other peoples limits.

### Directory Structure

Here we provide an overview of the directory structure:

- `\beacon_chain`: contains logic derived directly from the specification.
  E.g., shuffling algorithms, state transition logic and structs, block
validation, BLS crypto, etc.
- `\lighthouse`: contains logic specific to this client implementation. E.g.,
  CLI parsing, RPC end-points, databases, etc.
- `\network-libp2p`: contains a proof-of-concept libp2p implementation. Will be
  replaced once research around p2p has been finalized.

## Contact

The best place for discussion is the [sigp/lighthouse](https://gitter.im/sigp/lighthouse) gitter.
Ping @paulhauner or @AgeManning to get the quickest response.


# What is Ethereum 2.0

Ethereum 2.0 refers to a new blockchain currently under development
by the Ethereum Foundation and the Ethereum community. The Ethereum 2.0 blockchain
consists of 1,025 proof-of-stake blockchains; the "beacon chain" and 1,024
"shard chains".

## Beacon Chain

The Beacon Chain differs from existing blockchains such as Bitcoin and
Ethereum, in that it doesn't process "transactions", per say.  Instead, it
maintains a set of bonded (staked) validators and co-ordinates these to provide
services to a static set of "sub-blockchains" (shards). These shards process
normal transactions, such as "5 ETH from A to B", in parallel whilst deferring
consensus to the Beacon Chain.

Major services provided by the beacon chain to its shards include the following:

- A source of entropy, likely using a [RANDAO + VDF
  scheme](https://ethresear.ch/t/minimal-vdf-randomness-beacon/3566).
- Valdidator management, including:
    - Inducting and ejecting validators.
    - Delegating randomly-shuffled subsets of validators to validate shards.
    - Penalising and rewarding validators.
- Proof-of-stake consensus for shard chain blocks.

## Shard Chains

Shards can be thought of like CPU cores - they're a lane where transactions can
execute in series (one-after-another). Presently, Ethereum is single-core and
can only _fully_ process one transaction at a time. Sharding allows multiple
transactions to happen in parallel, greatly increasing the per-second
transaction capacity of Ethereum.

Each shard uses proof-of-stake and shares its validators (stakers) with the other
shards as the beacon chain rotates validators pseudo-randomly across shards.
Shards will likely be the basis of very interesting layer-2 transaction
processing schemes, however, we won't get into that here.

## The Proof-of-Work Chain

The proof-of-work chain will hold a contract that allows accounts to deposit 32
ETH, a BLS public key and some [other
parameters](https://github.com/ethereum/eth2.0-specs/blob/master/specs/casper_sharding_v2.1.md#pow-chain-changes)
to allow them to become Beacon Chain validators. Each Beacon Chain will
reference a PoW block hash allowing PoW clients to use the Beacon Chain as a
source of [Casper FFG finality](https://arxiv.org/abs/1710.09437), if desired.

## Ethereum 2.0 Progress

Ethereum 2.0 is not fully specified and there's no working implementation. Some
teams have demos available which indicate progress, but not a complete product.
We look forward to providing user functionality once we are ready to provide a
minimum-viable user experience.

The work-in-progress specification lives
[here](https://github.com/ethereum/eth2.0-specs/blob/master/specs/casper_sharding_v2.1.md)
in the [ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs)
repository. The spec is still in a draft phase, however there are several teams
already implementing it whilst the Ethereum Foundation research team fill in
the gaps. There is active discussion about the spec in the
[ethereum/sharding](https://gitter.im/ethereum/sharding) gitter channel. A
proof-of-concept implementation in Python is available at
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain).

Presently, the spec almost exclusively defines the Beacon Chain, which is the
focus of present development efforts. Progress on shard chain specification
will soon follow.

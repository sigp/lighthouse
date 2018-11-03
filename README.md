# Lighthouse: an Ethereum 2.0 client

[![Build Status](https://travis-ci.org/sigp/lighthouse.svg?branch=master)](https://travis-ci.org/sigp/lighthouse) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sigp/lighthouse?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

A work-in-progress, open-source implementation of the Ethereum 2.0 Beacon
Chain, maintained by Sigma Prime.

## Introduction

This readme is split into two major sections:

- [Lighthouse Client](#lighthouse-client): information about this
  implementation.
- [What is Ethereum 2.0](#what-is-ethereum-20): an introduction to Ethereum 2.0.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or the
[company website](https://sigmaprime.io).

## Lighthouse Client

Lighthouse is an open-source Ethereum 2.0 client that is currently under
development.  Designed as an Ethereum 2.0-only client, Lighthouse will not
re-implement the existing proof-of-work protocol. Maintaining a forward-focus
on Ethereum 2.0 ensures that Lighthouse avoids reproducing the high-quality
work already undertaken by existing projects. As such, Lighthouse will connect
to existing clients, such as
[Geth](https://github.com/ethereum/go-ethereum) or
[Parity-Ethereum](https://github.com/paritytech/parity-ethereum), via RPC to enable
present-Ethereum functionality.

### Goals

The purpose of this project is to further research and development towards a
secure, efficient, and decentralized Ethereum protocol, facilitated by a new
open-source Ethereum 2.0 client.

In addition to implementing a new client, the project seeks to maintain and
improve the Ethereum protocol wherever possible.

### Components

The following list describes some of the components actively under development
by the team:

- **BLS cryptography**: Lighthouse presently use the [Apache
  Milagro](https://milagro.apache.org/) cryptography library to create and
  verify BLS aggregate signatures. BLS signatures are core to Eth 2.0 as they
  allow the signatures of many validators to be compressed into a constant 96
  bytes and efficiently verified. The Lighthouse project is presently
  maintaining its own [BLS aggregates
  library](https://github.com/sigp/signature-schemes), gratefully forked from
  [@lovesh](https://github.com/lovesh).
- **DoS-resistant block pre-processing**: Processing blocks in proof-of-stake
  is more resource intensive than proof-of-work. As such, clients need to
  ensure that bad blocks can be rejected as efficiently as possible. At
  present, blocks having 10 million ETH staked can be processed in 0.006
  seconds, and invalid blocks are rejected even more quickly. See [issue
  #103](https://github.com/ethereum/beacon_chain/issues/103) on
  [ethereum/beacon_chain](https://github.com/ethereum/beacon_chain).
.
- **P2P networking**: Eth 2.0 will likely use the [libp2p
  framework](https://libp2p.io/). Lighthouse aims to work alongside
[Parity](https://www.parity.io/) to ensure
[libp2p-rust](https://github.com/libp2p/rust-libp2p) is fit-for-purpose.
- **Validator duties** : The project involves development of "validator
  services" for users who wish to stake ETH. To fulfill their duties,
  validators require a consistent view of the chain and the ability to vote
  upon blocks from both shard and beacon chains.
- **New serialization formats**: Lighthouse is working alongside researchers
  from the Ethereum Foundation to develop *simpleserialize* (SSZ), a
  purpose-built serialization format for sending information across a network.
  Check out the [SSZ
implementation](https://github.com/sigp/lighthouse/tree/master/beacon_chain/utils/ssz)
and this
[research](https://github.com/sigp/serialization_sandbox/blob/report/report/serialization_report.md)
on serialization formats for more information.
- **Casper FFG fork-choice**: The [Casper
  FFG](https://arxiv.org/abs/1710.09437) fork-choice rules allow the chain to
select a canonical chain in the case of a fork.
- **Efficient state transition logic**: State transition logic governs
  updates to the validator set as validators log in/out, penalizes/rewards
validators, rotates validators across shards, and implements other core tasks.
- **Fuzzing and testing environments**: Implementation of lab environments with
  continuous integration (CI) workflows, providing automated security analysis.

In addition to these components we are also working on database schemas, RPC
frameworks, specification development, database optimizations (e.g.,
bloom-filters), and tons of other interesting stuff (at least we think so).

### Contributing

**Lighthouse welcomes contributors with open-arms.**

Layer-1 infrastructure is a critical component for the ecosystem and relies
heavily on contributions from the community. Building Ethereum 2.0 is a huge
task and we refuse to conduct an inappropriate ICO or charge licensing fees.
Instead, we fund development through grants and support from Sigma Prime.

If you would like to learn more about Ethereum 2.0 and/or
[Rust](https://www.rust-lang.org/), we are more than happy to on-board you
and assign you some tasks. We aim to be as accepting and understanding as
possible; we are more than happy to up-skill contributors in exchange for their
assistance with the project.

Alternatively, if you are an ETH/Rust veteran, we'd love your input.  We're
always looking for the best way to implement things and welcome all 
respectful criticisms.

If you'd like to contribute, try having a look through the [open
issues](https://github.com/sigp/lighthouse/issues) (tip: look for the [good
first
issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
tag) and ping us on the [gitter](https://gitter.im/sigp/lighthouse) channel. We need
your support!

### Running

**NOTE: The cryptography libraries used in this implementation are
experimental. As such all cryptography is assumed to be insecure.**

This code-base is still very much under-development and does not provide any
user-facing functionality. For developers and researchers, there are several
tests and benchmarks which may be of interest. Few basic setups needed before starting like:

   1. Install [rustup](https://rustup.rs/).  It's a toolchain manager for Rust (Linux | macos | Windows). For installation run the below command in your terminal
   ```
        $ curl https://sh.rustup.rs -sSf | sh
```
   2. To configure your current shell run
  
   ```
        $ source $HOME/.cargo/env
```
   
   3. Use `rustup show` to get the info about the Rust setup. You will see active toolchain is in the stable version. 
   4. Run  `rustc --version` to get the version of rustup. For doing an update using` rustup update` .
   5. Navigate to the working directory.
   6. Run the test by using command `cargo test --all` . By running, it will pass all the required test cases. If you are doing it for the first time, then you can grab a coffee meantime. Usually, it takes time to build, compile and pass all test cases. If there is no error then, it means everything is working properly and it's time to get hand's dirty. In case, if there is an error, then please raise the [issue](https://github.com/sigp/lighthouse/issues).  We will help you.
   7. The alternative of the above step, You  can also run benchmarks by using `cargo bench --all`

##### Note:
Lighthouse presently runs on Rust `stable`, however, benchmarks currently require the
`nightly` version.

### Engineering Ethos

Lighthouse aims to produce many small easily-tested components, each separated
into individual crates wherever possible.

Generally, tests can be kept in the same file, as is typical in Rust.
Integration tests should be placed in the `tests` directory in the crate's
root.  Particularity large (line-count) tests should be placed into a separate
file.

A function is not considered complete until a test exists for it. We produce
tests to protect against regression (accidentally breaking things) and to
provide examples that help readers of the code base understand how functions
should (or should not) be used.

Each pull request is to be reviewed by at least one "core developer" (i.e.,
someone with write-access to the repository). This helps to ensure bugs are
detected, consistency is maintained, and responsibility of errors is dispersed.

Discussion must be respectful and intellectual. Have fun and make jokes, but
always respect the limits of other people.

### Directory Structure

Here we provide an overview of the directory structure:

- `/beacon_chain`: contains logic derived directly from the specification.
  E.g., shuffling algorithms, state transition logic and structs, block
validation, BLS crypto, etc.
- `/lighthouse`: contains logic specific to this client implementation. E.g.,
  CLI parsing, RPC end-points, databases, etc.

## Contact

The best place for discussion is the [sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).
Ping @paulhauner or @AgeManning to get the quickest response.


# What is Ethereum 2.0

Ethereum 2.0 refers to a new blockchain system currently under development by
the Ethereum Foundation and the Ethereum community. The Ethereum 2.0 blockchain
consists of 1,025 proof-of-stake blockchains. This includes the "beacon chain"
and 1,024 "shard chains".

## Beacon Chain

The concept of a beacon chain differs from existing blockchains, such as
Bitcoin and Ethereum, in that it doesn't process transactions per se. Instead,
it maintains a set of bonded (staked) validators and coordinates these to
provide services to a static set of *sub-blockchains* (i.e. shards). Each of
these shard blockchains processes normal transactions (e.g. "Transfer 5 ETH
from A to B") in parallel whilst deferring consensus mechanisms to the beacon
chain.

Major services provided by the beacon chain to its shards include the following:

- A source of entropy, likely using a [RANDAO + VDF
  scheme](https://ethresear.ch/t/minimal-vdf-randomness-beacon/3566).
- Validator management, including:
    - Inducting and ejecting validators.
    - Assigning randomly-shuffled subsets of validators to particular shards.
    - Penalizing and rewarding validators.
- Proof-of-stake consensus for shard chain blocks.

## Shard Chains

Shards are analogous to CPU cores - they're a resource where transactions can
execute in series (one-after-another). Presently, Ethereum is single-core and
can only _fully_ process one transaction at a time. Sharding allows processing
of multiple transactions simultaneously, greatly increasing the per-second
transaction capacity of Ethereum.

Each shard uses a proof-of-stake consensus mechanism and shares its validators
(stakers) with other shards. The beacon chain rotates validators
pseudo-randomly between different shards.  Shards will likely be the basis of
layer-2 transaction processing schemes, however, that is not in scope of this
discussion.

## The Proof-of-Work Chain

The present-Ethereum proof-of-work (PoW) chain will host a smart contract that
enables accounts to deposit 32 ETH, a BLS public key, and some [other
parameters](https://github.com/ethereum/eth2.0-specs/blob/master/specs/casper_sharding_v2.1.md#pow-chain-changes),
allowing them to become beacon chain validators. Each beacon chain will
reference a PoW block hash allowing PoW clients to use the beacon chain as a
source of [Casper FFG finality](https://arxiv.org/abs/1710.09437), if desired.

It is a requirement that ETH can move freely between shard chains, as well as between
Eth 2.0 and present-Ethereum blockchains. The exact mechanics of these transfers remain
an active topic of research and their details are yet to be confirmed.

## Ethereum 2.0 Progress

Ethereum 2.0 is not fully specified and a working implementation does not yet
exist. Some teams have demos available which indicate progress, but do not
constitute a complete product.  We look forward to providing user functionality
once we are ready to provide a minimum-viable user experience.

The work-in-progress Eth 2.0 specification lives
[here](https://github.com/ethereum/eth2.0-specs/blob/master/specs/casper_sharding_v2.1.md)
in the [ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs)
repository. The spec is still in a draft phase, however there are several teams
basing their Eth 2.0 implementations upon it while the Ethereum Foundation research
team continue to fill in the gaps. There is active discussion about the specification in the
[ethereum/sharding](https://gitter.im/ethereum/sharding) gitter channel. A
proof-of-concept implementation in Python is available at
[ethereum/beacon_chain](https://github.com/ethereum/beacon_chain).

Presently, the specification focuses almost exclusively on the beacon chain,
as it is the focus of current development efforts. Progress on shard chain
specification will soon follow.

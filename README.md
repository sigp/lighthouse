# Lighthouse: an Ethereum Serenity client

[![Build Status](https://travis-ci.org/sigp/lighthouse.svg?branch=master)](https://travis-ci.org/sigp/lighthouse) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sigp/lighthouse?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

A work-in-progress, open-source implementation of the Serenity Beacon
Chain, maintained by Sigma Prime.

The "Serenity" project is also known as "Ethereum 2.0" or "Shasper".

## Project Structure

The Lighthouse project is managed across four Github repositories:

- [sigp/lighthouse](https://github.com/sigp/lighthouse) (this repo): The
	"integration" repository which provides:
	- Project-wide documentation
	- A sub-module for each of the following repos.
	- A landing-page for users and contributors.
	- A triage point for issues.
	- In the future, various other integration tests and orchestration suites.
- [sigp/lighthouse-libs](https://github.com/sigp/lighthouse-libs): Contains
	Rust crates common to the entire Lighthouse project, including:
	- Pure specification logic (e.g., state transitions, etc)
	- SSZ (SimpleSerialize)
	- BLS Signature libraries
- [sigp/lighthouse-beacon](https://github.com/sigp/lighthouse-beacon): The
	beacon node binary, responsible for connection to peers across the
	network and maintaining a view of the Beacon Chain.
- [sigp/lighthouse-validator](https://github.com/sigp/lighthouse-validator):
	The validator client binary, which connects to a beacon node and fulfils
	the duties of a staked validator (producing and attesting to blocks).

## Contributing

We welcome new contributors and greatly appreciate the efforts from existing
contributors.

If you'd like to contribute to development on Lighthouse, we'd recommend
checking for [issues on the lighthouse-libs
repo](https://github.com/sigp/lighthouse-libs/issues) first, then checking the
other repositories.

If you don't find anything there, please reach out on the
[gitter](https://gitter.im/sigp/lighthouse) channel.

Additional resources:

- [ONBOARDING.md](docs/ONBOARDING.md): General on-boarding info,
	including style-guide.
- [LIGHTHOUSE.md](docs/LIGHTHOUSE.md): Project goals and ethos.
- [RUNNING.md](docs/RUNNING.md): Step-by-step on getting the code running.
- [SERENITY.md](docs/SERENITY.md): Introduction to Ethereum Serenity.

## Project Summary

Lighthouse is an open-source Ethereum Serenity client that is currently under
development. Designed as a Serenity-only client, Lighthouse will not
re-implement the existing proof-of-work protocol. Maintaining a forward-focus
on Ethereum Serenity ensures that Lighthouse avoids reproducing the high-quality
work already undertaken by existing projects. As such, Lighthouse will connect
to existing clients, such as
[Geth](https://github.com/ethereum/go-ethereum) or
[Parity-Ethereum](https://github.com/paritytech/parity-ethereum), via RPC to enable
present-Ethereum functionality.


### Components

The following list describes some of the components actively under development
by the team:

- **BLS cryptography**: Lighthouse presently use the [Apache
  Milagro](https://milagro.apache.org/) cryptography library to create and
  verify BLS aggregate signatures. BLS signatures are core to Serenity as they
  allow the signatures of many validators to be compressed into a constant 96
  bytes and efficiently verified. The Lighthouse project is presently
  maintaining its own [BLS aggregates
  library](https://github.com/sigp/signature-schemes), gratefully forked from
  [@lovesh](https://github.com/lovesh).
- **DoS-resistant block pre-processing**: Processing blocks in proof-of-stake
  is more resource intensive than proof-of-work. As such, clients need to
  ensure that bad blocks can be rejected as efficiently as possible. At
  present, blocks having 10 million ETH staked can be processed in 0.006
  seconds, and invalid blocks are rejected even more quickly. See
  [issue #103](https://github.com/ethereum/beacon_chain/issues/103) on
  [ethereum/beacon_chain](https://github.com/ethereum/beacon_chain).
- **P2P networking**: Serenity will likely use the [libp2p
  framework](https://libp2p.io/). Lighthouse is working alongside
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
implementation](https://github.com/sigp/lighthouse-libs/tree/master/ssz)
and this
[research](https://github.com/sigp/serialization_sandbox/blob/report/report/serialization_report.md)
on serialization formats for more information.
- **Fork-choice**: The current fork choice rule is
[*LMD Ghost*](https://vitalik.ca/general/2018/12/05/cbc_casper.html#lmd-ghost),
which effectively takes the latest messages and forms the canonical chain using
the [GHOST](https://eprint.iacr.org/2013/881.pdf) mechanism.
- **Efficient state transition logic**: State transition logic governs
  updates to the validator set as validators log in/out, penalizes/rewards
validators, rotates validators across shards, and implements other core tasks.
- **Fuzzing and testing environments**: Implementation of lab environments with
  continuous integration (CI) workflows, providing automated security analysis.

In addition to these components we are also working on database schemas, RPC
frameworks, specification development, database optimizations (e.g.,
bloom-filters), and tons of other interesting stuff (at least we think so).


## Contact

The best place for discussion is the [sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).
Ping @paulhauner or @AgeManning to get the quickest response.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or the
[company website](https://sigmaprime.io).

# Donations

We accept donations at the following Ethereum address. All donations go towards
funding development of Ethereum 2.0.

[`0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b`](https://etherscan.io/address/0x25c4a76e7d118705e7ea2e9b7d8c59930d8acd3b)

Alternatively, you can contribute via [Gitcoin Grant](https://gitcoin.co/grants/25/lighthouse-ethereum-20-client).

We appreciate all contributions to the project.

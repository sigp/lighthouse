# Lighthouse: an Ethereum Serenity client

[![Build Status](https://travis-ci.org/sigp/lighthouse.svg?branch=master)](https://travis-ci.org/sigp/lighthouse) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sigp/lighthouse?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

A work-in-progress, open-source implementation of the Serenity Beacon
Chain, maintained by Sigma Prime.

The "Serenity" project is also known as "Ethereum 2.0" or "Shasper".

## Lighthouse Client

Lighthouse is an open-source Ethereum Serenity client that is currently under
development. Designed as a Serenity-only client, Lighthouse will not
re-implement the existing proof-of-work protocol. Maintaining a forward-focus
on Ethereum Serenity ensures that Lighthouse avoids reproducing the high-quality
work already undertaken by existing projects. As such, Lighthouse will connect
to existing clients, such as
[Geth](https://github.com/ethereum/go-ethereum) or
[Parity-Ethereum](https://github.com/paritytech/parity-ethereum), via RPC to enable
present-Ethereum functionality.

### Further Reading

- [About Lighthouse](docs/lighthouse.md): Goals, Ideology and Ethos surrounding
this implementation.
- [What is Ethereum Serenity](docs/serenity.md): an introduction to Ethereum Serenity.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or the
[company website](https://sigmaprime.io).

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
implementation](https://github.com/sigp/lighthouse/tree/master/beacon_chain/utils/ssz)
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

### Directory Structure

Here we provide an overview of the directory structure:

- `beacon_chain/`: contains logic derived directly from the specification.
  E.g., shuffling algorithms, state transition logic and structs, block
validation, BLS crypto, etc.
- `lighthouse/'``: contains logic specific to this client implementation. E.g.,
  CLI parsing, RPC end-points, databases, etc.

### Running

**NOTE: The cryptography libraries used in this implementation are
experimental. As such all cryptography is assumed to be insecure.**

This code-base is still very much under-development and does not provide any
user-facing functionality. For developers and researchers, there are several
tests and benchmarks which may be of interest.

A few basic steps are needed to get set up:

   1. Install [rustup](https://rustup.rs/).  It's a toolchain manager for Rust (Linux | macos | Windows). For installation run the below command in your terminal
   ```
        $ curl https://sh.rustup.rs -sSf | sh
```
   2. To configure your current shell run:
  
   ```
        $ source $HOME/.cargo/env
```
   
   3. Use the command `rustup show` to get information about the Rust installation. You should see that the active toolchain is the stable version. 
   4. Run  `rustc --version` to check the installation and version of rust.
      - Updates can be performed using` rustup update` .
   5. Navigate to the working directory.
   6. Run the test by using command `cargo test --all` . By running, it will pass all the required test cases. If you are doing it for the first time, then you can grab a coffee meantime. Usually, it takes time to build, compile and pass all test cases. If there is no error then, it means everything is working properly and it's time to get hand's dirty. In case, if there is an error, then please raise the [issue](https://github.com/sigp/lighthouse/issues).  We will help you.
   7. As an alternative to, or instead of the above step, you may also run benchmarks by using the command `cargo bench --all`

##### Note:
Lighthouse presently runs on Rust `stable`, however, benchmarks currently require the
`nightly` version.

### Contributing

**Lighthouse welcomes contributors with open-arms.**

If you would like to learn more about Ethereum Serenity and/or
[Rust](https://www.rust-lang.org/), we are more than happy to on-board you
and assign you some tasks. We aim to be as accepting and understanding as
possible; we are more than happy to up-skill contributors in exchange for their
assistance with the project.

Alternatively, if you are an ETH/Rust veteran, we'd love your input.  We're
always looking for the best way to implement things and welcome all
respectful criticisms.

If you are looking to contribute, please head to our
[onboarding documentation](https://github.com/sigp/lighthouse/blob/master/docs/onboarding.md).

If you'd like to contribute, try having a look through the [open
issues](https://github.com/sigp/lighthouse/issues) (tip: look for the [good
first
issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
tag) and ping us on the [gitter](https://gitter.im/sigp/lighthouse) channel. We need
your support!

## Contact

The best place for discussion is the [sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).
Ping @paulhauner or @AgeManning to get the quickest response.

# Donations

If you support the cause, we could certainly use donations to help fund development:

`0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b`

# Lighthouse: an Ethereum Serenity client

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Gitter Badge]][Gitter Link]

[Build Status]: https://gitlab.sigmaprime.io/sigp/lighthouse/badges/master/build.svg
[Build Link]: https://gitlab.sigmaprime.io/sigp/lighthouse/pipelines
[Gitter Badge]: https://badges.gitter.im/Join%20Chat.svg
[Gitter Link]: https://gitter.im/sigp/lighthouse
[Doc Status]: https://img.shields.io/badge/docs-master-blue.svg
[Doc Link]: http://lighthouse-docs.sigmaprime.io/

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
- [Lighthouse Technical Documentation](http://lighthouse-docs.sigmaprime.io/): The Rust generated documentation, updated regularly.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or the
[company website](https://sigmaprime.io).

### Directory Structure

- [`beacon_node/`](beacon_node/): the "Beacon Node" binary and crates exclusively
	associated with it.
- [`docs/`](docs/): documentation related to the repository. This includes contributor
	guides, etc. (It does not include code documentation, which can be produced with `cargo doc`).
- [`eth2/`](eth2/): Crates containing common logic across the Lighthouse project. For
	example: Ethereum 2.0 types ([`BeaconBlock`](eth2/types/src/beacon_block.rs), [`BeaconState`](eth2/types/src/beacon_state.rs), etc) and
	SimpleSerialize (SSZ).
- [`protos/`](protos/): protobuf/gRPC definitions that are common across the Lighthouse project.
- [`validator_client/`](validator_client/): the "Validator Client" binary and crates exclusively
	associated with it.

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
implementation](https://github.com/ethereum/eth2.0-specs/blob/00aa553fee95963b74fbec84dbd274d7247b8a0e/specs/simple-serialize.md)
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

### Running

**NOTE: The cryptography libraries used in this implementation are
experimental. As such all cryptography is assumed to be insecure.**

This code-base is still very much under-development and does not provide any
user-facing functionality. For developers and researchers, there are several
tests and benchmarks which may be of interest.

A few basic steps are needed to get set up:

   1. Install [rustup](https://rustup.rs/).  It's a toolchain manager for Rust (Linux | macOS | Windows). For installation, download the script with `$ curl -f https://sh.rustup.rs > rustup.sh`, review its content (e.g. `$ less ./rustup.sh`) and run the script `$ ./rustup.sh` (you may need to change the permissions to allow execution, i.e. `$ chmod +x rustup.sh`) 
   2. (Linux & MacOS) To configure your current shell run: `$ source $HOME/.cargo/env`
   3. Use the command `rustup show` to get information about the Rust installation. You should see that the
   active toolchain is the stable version.
   4. Run `rustc --version` to check the installation and version of rust.
      - Updates can be performed using` rustup update` .
   5. Install build dependencies (Arch packages are listed here, your distribution will likely be similar):
	  - `clang`: required by RocksDB.
	  - `protobuf`: required for protobuf serialization (gRPC).
	  - `cmake`: required for building protobuf.
	  - `git-lfs`: The Git extension for [Large File Support](https://git-lfs.github.com/) (required for EF tests submodule).
   6. Navigate to the working directory.
   7. If you haven't already, clone the repository with submodules: `git clone --recursive https://github.com/sigp/lighthouse`.
		Alternatively, run `git submodule init` in a repository which was cloned without submodules.
   8. Run the test by using command `cargo test --all --release`. By running, it will pass all the required test cases.
        If you are doing it for the first time, then you can grab a coffee in the meantime. Usually, it takes time
        to build, compile and pass all test cases. If there is no error then it means everything is working properly
        and it's time to get your hands dirty.
        In case, if there is an error, then please raise the [issue](https://github.com/sigp/lighthouse/issues).
        We will help you.
   9. As an alternative to, or instead of the above step, you may also run benchmarks by using
        the command `cargo bench --all`

##### Note:
Lighthouse presently runs on Rust `stable`, however, benchmarks currently require the
`nightly` version.

##### Note for Windows users:
Perl may also be required to build lighthouse. You can install [Strawberry Perl](http://strawberryperl.com/),
or alternatively use a choco install command `choco install strawberryperl`.

Additionally, the dependency `protoc-grpcio v0.3.1` is reported to have issues compiling in Windows. You can specify
a known working version by editing version in protos/Cargo.toml's "build-dependencies" section to
`protoc-grpcio = "<=0.3.0"`.

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

`0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b` (donation.sigmaprime.eth)
